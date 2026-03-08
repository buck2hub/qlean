use std::{
    ffi::OsStr,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    time::{Duration, timeout},
};
use tracing::{debug, info};

use crate::utils::{QleanDirs, ensure_extraction_prerequisites};

fn default_root_arg() -> String {
    "root=/dev/vda1".to_string()
}

pub trait ImageAction {
    /// Download the image from remote source
    fn download(&self, name: &str) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Extract kernel and initrd from the image
    fn extract(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(PathBuf, PathBuf)>> + Send;
    /// Get the distro type
    fn distro(&self) -> Distro;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta<A: ImageAction> {
    pub name: String,
    pub path: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    #[serde(default = "default_root_arg")]
    pub root_arg: String,
    #[serde(skip)]
    pub vendor: A,
    pub checksum: ShaSum,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Distro {
    Debian,
    Ubuntu,
    Fedora,
    Arch,
    Custom,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum ShaType {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaSum {
    pub path: PathBuf,
    pub sha_type: ShaType,
}

/// Source of a file: URL or local file path
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImageSource {
    Url(String),
    LocalPath(PathBuf),
}

/// Configuration for custom images - supports two modes:
/// 1. Image only (requires guestfish for extraction)
/// 2. Image + pre-extracted kernel/initrd
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomImageConfig {
    // Image file (required)
    pub image_source: ImageSource,
    pub image_hash: String,
    pub image_hash_type: ShaType,

    // Optional: pre-extracted kernel and initrd (avoids guestfish extraction)
    pub kernel_source: Option<ImageSource>,
    pub kernel_hash: Option<String>,
    pub initrd_source: Option<ImageSource>,
    pub initrd_hash: Option<String>,
}

/// Normalize checksum entry names across common checksum file formats.
fn normalize_checksum_name(name: &str) -> &str {
    name.trim_start_matches('*').trim_start_matches("./")
}

fn checksum_name_matches(entry_name: &str, wanted: &str) -> bool {
    let entry = normalize_checksum_name(entry_name);
    let wanted = normalize_checksum_name(wanted);
    if entry == wanted {
        return true;
    }
    if !wanted.contains('/')
        && let Some(base) = entry.rsplit('/').next()
    {
        return base == wanted;
    }
    false
}

/// Parse a checksum file and return the hash for a given filename.
///
/// Supports common formats:
/// 1) "<hex>  <filename>" (including "*filename" and "./filename")
/// 2) "SHA256 (<filename>) = <hex>" / "SHA512 (<filename>) = <hex>"
pub fn find_hash_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    let mut parts = checksums_text.split_whitespace();
    while let Some(hash) = parts.next() {
        let Some(fname) = parts.next() else { break };
        if checksum_name_matches(fname, filename) {
            return Some(hash.to_string());
        }
    }

    for line in checksums_text.lines() {
        let line = line.trim();
        for prefix in ["SHA256 (", "SHA512 ("] {
            if let Some(rest) = line.strip_prefix(prefix)
                && let Some((entry_name, hash_part)) = rest.split_once(") = ")
                && checksum_name_matches(entry_name, filename)
            {
                return Some(hash_part.trim().to_string());
            }
        }
    }

    None
}

const IMAGE_SOURCES_CONFIG_PATH: &str = "qlean-images.toml";

#[derive(Debug, Deserialize)]
struct ImageSourcesConfig {
    debian: RemoteImageConfig,
    ubuntu: RemoteImageConfig,
    fedora: RemoteImageConfig,
    arch: RemoteImageConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct RemoteImageConfig {
    image_url: String,
    checksum_url: String,
    checksum_entry: String,
    checksum_type: ShaType,
}

impl ImageSourcesConfig {
    fn for_distro(&self, distro: Distro) -> Result<&RemoteImageConfig> {
        match distro {
            Distro::Debian => Ok(&self.debian),
            Distro::Ubuntu => Ok(&self.ubuntu),
            Distro::Fedora => Ok(&self.fedora),
            Distro::Arch => Ok(&self.arch),
            Distro::Custom => bail!("custom images do not use qlean-images.toml"),
        }
    }
}

fn image_sources_config_path() -> PathBuf {
    PathBuf::from(IMAGE_SOURCES_CONFIG_PATH)
}

async fn load_image_sources_config() -> Result<ImageSourcesConfig> {
    let path = image_sources_config_path();
    let content = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| {
            format!(
                "failed to read image source config at {}. Copy or edit qlean-images.toml before creating distro images",
                path.display()
            )
        })?;

    toml::from_str(&content)
        .with_context(|| format!("failed to parse TOML from {}", path.display()))
}

async fn fetch_text(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("qlean/0.2 (image-fetch)")
        .build()
        .with_context(|| "failed to build HTTP client")?;

    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {}", url))?;
    let status = resp.status();
    anyhow::ensure!(status.is_success(), "GET {} failed: {}", url, status);

    resp.text()
        .await
        .with_context(|| format!("failed reading body from {}", url))
}

async fn fetch_expected_hash(config: &RemoteImageConfig) -> Result<String> {
    let checksums_text = fetch_text(&config.checksum_url)
        .await
        .with_context(|| format!("failed to fetch checksum file from {}", config.checksum_url))?;

    find_hash_for_file(&checksums_text, &config.checksum_entry).with_context(|| {
        format!(
            "checksum file {} did not contain an entry for {}",
            config.checksum_url, config.checksum_entry
        )
    })
}

async fn download_remote_image(name: &str, distro: Distro) -> Result<()> {
    let dirs = QleanDirs::new()?;
    let image_path = dirs.images.join(name).join(format!("{}.qcow2", name));

    let sources = load_image_sources_config().await?;
    let config = sources.for_distro(distro)?;
    let expected_hash = fetch_expected_hash(config).await?;

    materialize_source_with_hash(
        &ImageSource::Url(config.image_url.clone()),
        &image_path,
        &expected_hash,
        config.checksum_type.clone(),
    )
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming hash functions - optimized for release mode performance
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

/// Compute SHA-256 hash using streaming approach with sync I/O
/// This provides 7-27% better performance than shell commands in release mode
pub async fn compute_sha256_streaming(path: &Path) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024]; // 64 KB buffer

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| "failed to read file during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .with_context(|| "hash computation task failed")?
}

/// Compute SHA-512 hash using streaming approach with sync I/O
pub async fn compute_sha512_streaming(path: &Path) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;

        let mut hasher = Sha512::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| "failed to read file during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .with_context(|| "hash computation task failed")?
}

/// Download a remote file and compute its hash in a single pass.
async fn stream_download_with_hash(
    url: &str,
    dest_path: &PathBuf,
    hash_type: ShaType,
) -> Result<String> {
    let tmp_path = dest_path.with_extension("part");

    debug!("Downloading {} to {}", url, dest_path.display());

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(20))
        .user_agent("qlean/0.2 (image-download)")
        .build()
        .with_context(|| "failed to build HTTP client")?;

    info!("Downloading image from {}", url);
    let response = tokio::time::timeout(std::time::Duration::from_secs(30), client.get(url).send())
        .await
        .with_context(|| format!("timed out before response headers from {}", url))?
        .with_context(|| format!("failed to download from {}", url))?;

    let status = response.status();
    let total_size = response.content_length();
    anyhow::ensure!(status.is_success(), "GET {} failed: {}", url, status);
    if let Some(total) = total_size {
        info!("Remote size: {} MiB ({})", total / (1024 * 1024), url);
    }

    if let Some(parent) = tmp_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }

    let _ = tokio::fs::remove_file(&tmp_path).await;

    let mut file = File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create file at {}", tmp_path.display()))?;

    let mut stream = response.bytes_stream();
    let idle = std::time::Duration::from_secs(60);
    let mut downloaded: u64 = 0;
    let mut last_report: u64 = 0;
    let report_step: u64 = 8 * 1024 * 1024;
    let mut last_report_at = std::time::Instant::now();

    let hash = match hash_type {
        ShaType::Sha256 => {
            let mut h = Sha256::new();
            loop {
                let next = tokio::time::timeout(idle, stream.next())
                    .await
                    .with_context(|| {
                        format!("download stalled for {} (>{:?} without data)", url, idle)
                    })?;
                let Some(chunk) = next else { break };
                let chunk = chunk.with_context(|| "failed to read chunk")?;
                downloaded += chunk.len() as u64;
                let now = std::time::Instant::now();
                if downloaded - last_report >= report_step
                    || (downloaded > 0
                        && now.duration_since(last_report_at) >= std::time::Duration::from_secs(10))
                {
                    last_report = downloaded;
                    last_report_at = now;
                    if let Some(total) = total_size {
                        info!(
                            "Download progress: {}/{} MiB ({})",
                            downloaded / (1024 * 1024),
                            total / (1024 * 1024),
                            url
                        );
                    } else {
                        info!(
                            "Download progress: {} MiB ({})",
                            downloaded / (1024 * 1024),
                            url
                        );
                    }
                }
                h.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .with_context(|| "failed to write chunk")?;
            }
            format!("{:x}", h.finalize())
        }
        ShaType::Sha512 => {
            let mut h = Sha512::new();
            loop {
                let next = tokio::time::timeout(idle, stream.next())
                    .await
                    .with_context(|| {
                        format!("download stalled for {} (>{:?} without data)", url, idle)
                    })?;
                let Some(chunk) = next else { break };
                let chunk = chunk.with_context(|| "failed to read chunk")?;
                downloaded += chunk.len() as u64;
                let now = std::time::Instant::now();
                if downloaded - last_report >= report_step
                    || (downloaded > 0
                        && now.duration_since(last_report_at) >= std::time::Duration::from_secs(10))
                {
                    last_report = downloaded;
                    last_report_at = now;
                    if let Some(total) = total_size {
                        info!(
                            "Download progress: {}/{} MiB ({})",
                            downloaded / (1024 * 1024),
                            total / (1024 * 1024),
                            url
                        );
                    } else {
                        info!(
                            "Download progress: {} MiB ({})",
                            downloaded / (1024 * 1024),
                            url
                        );
                    }
                }
                h.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .with_context(|| "failed to write chunk")?;
            }
            format!("{:x}", h.finalize())
        }
    };

    file.flush().await.with_context(|| "failed to flush file")?;

    tokio::fs::rename(&tmp_path, dest_path)
        .await
        .with_context(|| {
            format!(
                "failed to move {} -> {}",
                tmp_path.display(),
                dest_path.display()
            )
        })?;

    info!(
        "Download complete: {} MiB ({})",
        downloaded / (1024 * 1024),
        url
    );
    Ok(hash)
}

/// Materialize a source file into `dest` and verify it against the expected hash.
async fn materialize_source_with_hash(
    source: &ImageSource,
    dest: &PathBuf,
    expected_hash: &str,
    hash_type: ShaType,
) -> Result<()> {
    match source {
        ImageSource::Url(url) => {
            if dest.exists() {
                let existing = match &hash_type {
                    ShaType::Sha256 => compute_sha256_streaming(dest).await,
                    ShaType::Sha512 => compute_sha512_streaming(dest).await,
                };
                if let Ok(h) = existing
                    && h.eq_ignore_ascii_case(expected_hash)
                {
                    return Ok(());
                }
            }

            let computed = stream_download_with_hash(url, dest, hash_type.clone()).await?;
            anyhow::ensure!(
                computed.eq_ignore_ascii_case(expected_hash),
                "hash mismatch: expected {}, got {}",
                expected_hash,
                computed
            );
        }
        ImageSource::LocalPath(src) => {
            anyhow::ensure!(src.exists(), "file does not exist: {}", src.display());
            tokio::fs::copy(src, dest).await?;

            let computed = match hash_type {
                ShaType::Sha256 => compute_sha256_streaming(dest).await?,
                ShaType::Sha512 => compute_sha512_streaming(dest).await?,
            };

            anyhow::ensure!(
                computed.eq_ignore_ascii_case(expected_hash),
                "hash mismatch: expected {}, got {}",
                expected_hash,
                computed
            );
        }
    }
    Ok(())
}

impl<A: ImageAction + std::default::Default> ImageMeta<A> {
    /// Create a new image by downloading and extracting
    pub async fn create(name: &str) -> Result<Self> {
        debug!("Fetching image {} ...", name);

        let dirs = QleanDirs::new()?;

        if let Ok(image) = Self::load(name).await {
            debug!("Using cached image.");
            return Ok(image);
        }

        let image_dir = dirs.images.join(name);
        if image_dir.exists() {
            tokio::fs::remove_dir_all(&image_dir).await?;
        }
        tokio::fs::create_dir_all(&image_dir).await?;

        let distro_action = A::default();
        let distro = distro_action.distro();

        distro_action.download(name).await?;

        let image_path = image_dir.join(format!("{}.qcow2", name));
        let (kernel, initrd) = distro_action.extract(name).await?;
        let checksum_path = image_dir.join("checksums");
        let root_arg = match distro {
            Distro::Ubuntu => detect_root_arg(&image_path)
                .await
                .unwrap_or_else(|_| default_root_arg()),
            Distro::Debian | Distro::Fedora | Distro::Arch => detect_root_arg(&image_path).await?,
            Distro::Custom => unreachable!("custom images use create_with_action()"),
        };
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
            root_arg,
            checksum,
            name: name.to_string(),
            vendor: distro_action,
        };

        image.save(name).await?;

        Ok(image)
    }

    /// Load image metadata from disk and validate checksums
    async fn load(name: &str) -> Result<Self> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = tokio::fs::read_to_string(&json_path)
            .await
            .with_context(|| format!("failed to read config file at {}", json_path.display()))?;

        let mut image: ImageMeta<A> = serde_json::from_str(&json_content)
            .with_context(|| format!("failed to parse JSON from {}", json_path.display()))?;

        // Older caches may contain a `root=` token with a trailing ':' (e.g. `root=/dev/vda3:`),
        // which causes direct-kernel boot to hang forever waiting for a non-existent device.
        // Sanitize on load so users don't have to manually delete their image cache.
        image.root_arg = image
            .root_arg
            .split_whitespace()
            .map(|t| {
                if let Some(rest) = t.strip_prefix("root=") {
                    let clean = rest.trim_end_matches(':');
                    format!("root={clean}")
                } else {
                    t.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");

        let kernel_ok = image.kernel.exists()
            && !image
                .kernel
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".unavailable"))
                .unwrap_or(false)
            && std::fs::metadata(&image.kernel)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        let initrd_ok = image.initrd.exists()
            && !image
                .initrd
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".unavailable"))
                .unwrap_or(false)
            && std::fs::metadata(&image.initrd)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        if !kernel_ok || !initrd_ok {
            bail!("cached image is missing valid kernel/initrd artifacts; recreate is required");
        }

        let checksum_dir = dirs.images.join(name);
        let checksum_command = match image.checksum.sha_type {
            ShaType::Sha256 => "sha256sum",
            ShaType::Sha512 => "sha512sum",
        };

        let output = tokio::process::Command::new(checksum_command)
            .arg("-c")
            .arg(&image.checksum.path)
            .arg("--quiet")
            .current_dir(&checksum_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute {} -c", checksum_command))?;

        if !output.status.success() {
            bail!(
                "checksum verification failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(image)
    }
}

// Special create method for Custom images (non-Default trait)
impl<A: ImageAction> ImageMeta<A> {
    /// Save image metadata to disk using streaming hash.
    async fn save(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = serde_json::to_string_pretty(&self)
            .with_context(|| "failed to serialize image config to JSON")?;

        tokio::fs::write(&json_path, json_content)
            .await
            .with_context(|| format!("failed to write image config to {}", json_path.display()))?;

        // Use streaming hash for best performance (7-27% faster in release mode).
        let (image_hash, kernel_hash, initrd_hash) = match self.checksum.sha_type {
            ShaType::Sha256 => (
                compute_sha256_streaming(&self.path).await?,
                compute_sha256_streaming(&self.kernel).await?,
                compute_sha256_streaming(&self.initrd).await?,
            ),
            ShaType::Sha512 => (
                compute_sha512_streaming(&self.path).await?,
                compute_sha512_streaming(&self.kernel).await?,
                compute_sha512_streaming(&self.initrd).await?,
            ),
        };

        let image_filename = self
            .path
            .file_name()
            .with_context(|| "failed to get image filename")?
            .to_string_lossy();
        let kernel_filename = self
            .kernel
            .file_name()
            .with_context(|| "failed to get kernel filename")?
            .to_string_lossy();
        let initrd_filename = self
            .initrd
            .file_name()
            .with_context(|| "failed to get initrd filename")?
            .to_string_lossy();

        let checksum_content = format!(
            "{}  {}\n{}  {}\n{}  {}\n",
            image_hash, image_filename, kernel_hash, kernel_filename, initrd_hash, initrd_filename
        );

        tokio::fs::write(&self.checksum.path, checksum_content)
            .await
            .with_context(|| {
                format!(
                    "failed to write checksum file to {}",
                    self.checksum.path.display()
                )
            })?;

        Ok(())
    }

    /// Create image with custom action for non-Default implementations
    pub async fn create_with_action(name: &str, action: A) -> Result<Self> {
        debug!("Fetching image {} with custom action ...", name);

        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        if image_dir.exists() {
            tokio::fs::remove_dir_all(&image_dir).await?;
        }
        tokio::fs::create_dir_all(&image_dir).await?;

        action.download(name).await?;

        let image_path = image_dir.join(format!("{}.qcow2", name));
        let (kernel, initrd) = action.extract(name).await?;
        let checksum_path = image_dir.join("checksums");
        let root_arg = detect_root_arg(&image_path)
            .await
            .unwrap_or_else(|_| default_root_arg());
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
            root_arg,
            checksum,
            name: name.to_string(),
            vendor: action,
        };

        image.save(name).await?;

        Ok(image)
    }
}

fn format_guestfs_failure(program: &str, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let details = match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!(
            "{}
{}",
            stdout, stderr
        ),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => "(no output)".to_string(),
    };

    format!(
        "{program} failed using the host libguestfs installation:
{details}
Qlean does not provision libguestfs appliances or other fallback paths at runtime.
Install/repair the host libguestfs-tools setup and verify it with:
  LIBGUESTFS_BACKEND=direct libguestfs-test-tool"
    )
}

async fn run_guestfs_tool(
    program: &str,
    args: &[&OsStr],
    current_dir: &Path,
) -> Result<std::process::Output> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.env("LIBGUESTFS_BACKEND", "direct")
        .current_dir(current_dir);
    for a in args {
        cmd.arg(a);
    }

    let output = timeout(Duration::from_secs(180), cmd.output())
        .await
        .with_context(|| format!("{program} timed out after 180s (libguestfs)"))?
        .with_context(|| format!("failed to execute {program}"))?;

    if !output.status.success() {
        bail!("{}", format_guestfs_failure(program, &output));
    }

    Ok(output)
}

async fn guestfish_ls_boot(image_dir: &Path, file_name: &str) -> Result<String> {
    let args = [
        OsStr::new("--ro"),
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new("-i"),
        OsStr::new("ls"),
        OsStr::new("/boot"),
    ];
    let output = run_guestfs_tool("guestfish", &args, image_dir).await?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn virt_copy_out(image_dir: &Path, file_name: &str, src: &str, _kind: &str) -> Result<()> {
    let args = [
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new(src),
        OsStr::new("."),
    ];
    let _output = run_guestfs_tool("virt-copy-out", &args, image_dir).await?;
    Ok(())
}

async fn extract_boot_artifacts_guestfs(
    image_dir: &Path,
    file_name: &str,
    distro: Distro,
) -> Result<(PathBuf, PathBuf)> {
    ensure_extraction_prerequisites().await?;

    let boot_dir = image_dir.join("boot");
    let _ = tokio::fs::remove_dir_all(&boot_dir).await;

    virt_copy_out(image_dir, file_name, "/boot", "boot directory").await?;

    anyhow::ensure!(
        boot_dir.exists(),
        "virt-copy-out did not extract /boot into {}",
        image_dir.display()
    );

    let files = collect_files_recursive(&boot_dir).with_context(|| {
        format!(
            "failed to scan extracted boot tree in {}",
            boot_dir.display()
        )
    })?;

    let kernel_src = choose_kernel_file(&files, distro.clone())
        .with_context(|| "failed to find kernel file in extracted /boot")?;
    let initrd_src = choose_initrd_file(&files, distro)
        .with_context(|| "failed to find initrd file in extracted /boot")?;

    let kernel_name = kernel_src
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| "invalid kernel filename")?
        .to_string();
    let initrd_name = initrd_src
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| "invalid initrd filename")?
        .to_string();

    let kernel_path = image_dir.join(&kernel_name);
    let initrd_path = image_dir.join(&initrd_name);

    fs::copy(&kernel_src, &kernel_path).with_context(|| {
        format!(
            "failed to copy extracted kernel {} -> {}",
            kernel_src.display(),
            kernel_path.display()
        )
    })?;
    fs::copy(&initrd_src, &initrd_path).with_context(|| {
        format!(
            "failed to copy extracted initrd {} -> {}",
            initrd_src.display(),
            initrd_path.display()
        )
    })?;

    let kernel_args_path = kernel_args_hint_path(image_dir);
    if let Some(args) = choose_kernel_options(&files, &kernel_name) {
        fs::write(&kernel_args_path, args).with_context(|| {
            format!(
                "failed to write kernel args hint in {}",
                image_dir.display()
            )
        })?;
    } else {
        let _ = fs::remove_file(&kernel_args_path);
    }
    let _ = fs::remove_file(root_hint_path(image_dir));

    let _ = tokio::fs::remove_dir_all(&boot_dir).await;
    Ok((kernel_path, initrd_path))
}

fn root_hint_path(image_dir: &Path) -> PathBuf {
    image_dir.join(".root-partition")
}

fn kernel_args_hint_path(image_dir: &Path) -> PathBuf {
    image_dir.join(".kernel-args")
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    u32::from_le_bytes(arr)
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    u64::from_le_bytes(arr)
}

#[derive(Debug, Clone)]
struct PartitionSlice {
    number: usize,
    start_lba: u64,
    sectors: u64,
}

fn parse_mbr_partitions(mbr: &[u8]) -> Vec<PartitionSlice> {
    let mut parts = Vec::new();
    for idx in 0..4usize {
        let off = 446 + idx * 16;
        let entry = &mbr[off..off + 16];
        let part_type = entry[4];
        if part_type == 0 {
            continue;
        }
        let start_lba = read_u32_le(&entry[8..12]) as u64;
        let sectors = read_u32_le(&entry[12..16]) as u64;
        if start_lba > 0 && sectors > 0 {
            parts.push(PartitionSlice {
                number: idx + 1,
                start_lba,
                sectors,
            });
        }
    }
    parts
}

fn parse_gpt_partitions(raw_path: &Path) -> Result<Vec<PartitionSlice>> {
    let mut f = fs::File::open(raw_path)
        .with_context(|| format!("failed to open {}", raw_path.display()))?;

    let mut header = [0u8; 512];
    f.seek(SeekFrom::Start(512))
        .with_context(|| format!("failed to seek GPT header in {}", raw_path.display()))?;
    f.read_exact(&mut header)
        .with_context(|| format!("failed to read GPT header from {}", raw_path.display()))?;

    anyhow::ensure!(
        &header[0..8] == b"EFI PART",
        "{} does not contain a GPT header",
        raw_path.display()
    );

    let entries_lba = read_u64_le(&header[72..80]);
    let num_entries = read_u32_le(&header[80..84]) as usize;
    let entry_size = read_u32_le(&header[84..88]) as usize;
    anyhow::ensure!(entry_size >= 56, "invalid GPT entry size: {}", entry_size);

    let max_entries = num_entries.min(256);
    let table_len = max_entries
        .checked_mul(entry_size)
        .with_context(|| "GPT partition table size overflow")?;
    let mut table = vec![0u8; table_len];
    f.seek(SeekFrom::Start(entries_lba.saturating_mul(512)))
        .with_context(|| format!("failed to seek GPT entries in {}", raw_path.display()))?;
    f.read_exact(&mut table)
        .with_context(|| format!("failed to read GPT entries from {}", raw_path.display()))?;

    let mut parts = Vec::new();
    for idx in 0..max_entries {
        let off = idx * entry_size;
        let entry = &table[off..off + entry_size];
        if entry[0..16].iter().all(|b| *b == 0) {
            continue;
        }

        let start_lba = read_u64_le(&entry[32..40]);
        let end_lba = read_u64_le(&entry[40..48]);
        if start_lba == 0 || end_lba < start_lba {
            continue;
        }

        parts.push(PartitionSlice {
            number: idx + 1,
            start_lba,
            sectors: end_lba - start_lba + 1,
        });
    }

    Ok(parts)
}

fn list_partitions(raw_path: &Path) -> Result<Vec<PartitionSlice>> {
    let mut mbr = [0u8; 512];
    let mut f = fs::File::open(raw_path)
        .with_context(|| format!("failed to open {}", raw_path.display()))?;
    f.read_exact(&mut mbr)
        .with_context(|| format!("failed to read MBR from {}", raw_path.display()))?;

    anyhow::ensure!(
        mbr[510] == 0x55 && mbr[511] == 0xAA,
        "{} does not look like a bootable disk image",
        raw_path.display()
    );

    let protective_gpt = (0..4usize).any(|idx| mbr[446 + idx * 16 + 4] == 0xEE);
    let mut parts = if protective_gpt {
        parse_gpt_partitions(raw_path)?
    } else {
        parse_mbr_partitions(&mbr)
    };

    parts.sort_by(|a, b| {
        b.sectors
            .cmp(&a.sectors)
            .then_with(|| a.number.cmp(&b.number))
    });
    anyhow::ensure!(
        !parts.is_empty(),
        "failed to find any partitions in {}",
        raw_path.display()
    );
    Ok(parts)
}

fn collect_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.with_context(|| format!("failed while scanning {}", root.display()))?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

fn choose_kernel_file(files: &[PathBuf], distro: Distro) -> Option<PathBuf> {
    let mut candidates = files
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| match distro {
                    Distro::Fedora => n.starts_with("vmlinuz") && !n.contains("rescue"),
                    Distro::Arch => n.starts_with("vmlinuz"),
                    _ => n.starts_with("vmlinuz"),
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.into_iter().last()
}

fn choose_initrd_file(files: &[PathBuf], distro: Distro) -> Option<PathBuf> {
    let mut candidates = files
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| match distro {
                    Distro::Ubuntu | Distro::Debian => n.starts_with("initrd.img"),
                    Distro::Fedora => {
                        n.starts_with("initramfs") && n.ends_with(".img") && !n.contains("rescue")
                    }
                    Distro::Arch => {
                        n.starts_with("initramfs")
                            && n.ends_with(".img")
                            && n.contains("linux")
                            && !n.contains("fallback")
                    }
                    Distro::Custom => false,
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();

    if candidates.is_empty() && matches!(distro, Distro::Arch) {
        candidates = files
            .iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| {
                        n.starts_with("initramfs") && n.ends_with(".img") && n.contains("linux")
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();
    }

    candidates.sort();
    candidates.into_iter().last()
}

fn normalize_kernel_options(raw: &str) -> Option<String> {
    let tokens = raw
        .split_whitespace()
        .filter(|token| !token.is_empty() && *token != "ro" && *token != "rw")
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

fn resolve_kernelopts_from_grub_cfg(content: &str) -> Option<String> {
    // Fedora/GRUB often stores a full kernel command line in a variable called "kernelopts",
    // referenced from BLS entries as: `options $kernelopts`.
    //
    // We intentionally keep this parser lightweight and dependency-free.
    for line in content.lines() {
        let trimmed = line.trim();
        // Common forms:
        //   set kernelopts="root=UUID=... ro ..."
        //   set kernelopts='root=UUID=... ro ...'
        if let Some(rest) = trimmed.strip_prefix("set kernelopts=") {
            let rest = rest.trim();
            if let Some(stripped) = rest.strip_prefix('"')
                && let Some(end) = stripped.find('"')
            {
                return Some(stripped[..end].to_string());
            }
            if let Some(stripped) = rest.strip_prefix('\'')
                && let Some(end) = stripped.find('\'')
            {
                return Some(stripped[..end].to_string());
            }
            // Fallback: no quotes, take the remainder of the token.
            let first = rest.split_whitespace().next().unwrap_or("");
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }

        // Some grub.cfg variants assign without the "set" keyword.
        if let Some(idx) = trimmed.find("kernelopts=") {
            let rest = trimmed[idx + "kernelopts=".len()..].trim();
            if let Some(stripped) = rest.strip_prefix('"')
                && let Some(end) = stripped.find('"')
            {
                return Some(stripped[..end].to_string());
            }
            if let Some(stripped) = rest.strip_prefix('\'')
                && let Some(end) = stripped.find('\'')
            {
                return Some(stripped[..end].to_string());
            }
        }
    }
    None
}

fn resolve_kernelopts_from_grubenv(bytes: &[u8]) -> Option<String> {
    // grubenv is a binary environment block, but it commonly contains plain ASCII entries
    // like: `kernelopts=root=UUID=... ro ...`.
    let needle = b"kernelopts=";
    let pos = bytes.windows(needle.len()).position(|w| w == needle)?;
    let start = pos + needle.len();
    let mut end = start;
    while end < bytes.len() {
        let b = bytes[end];
        if b == b'\n' || b == 0 {
            break;
        }
        end += 1;
    }
    let s = String::from_utf8_lossy(&bytes[start..end])
        .trim()
        .to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn resolve_kernelopts(files: &[PathBuf]) -> Option<String> {
    // Prefer grub.cfg (human-readable).
    for path in files.iter() {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == "grub.cfg")
            .unwrap_or(false)
            && let Ok(content) = fs::read_to_string(path)
            && let Some(v) = resolve_kernelopts_from_grub_cfg(&content)
        {
            return Some(v);
        }
    }

    // Fallback: scan grubenv blocks.
    for path in files.iter() {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == "grubenv")
            .unwrap_or(false)
            && let Ok(bytes) = fs::read(path)
            && let Some(v) = resolve_kernelopts_from_grubenv(&bytes)
        {
            return Some(v);
        }
    }

    None
}

fn expand_kernelopts(options: &str, kernelopts: Option<&str>) -> Option<String> {
    let ko = kernelopts?;
    if options.contains("$kernelopts") || options.contains("${kernelopts}") {
        let expanded = options
            .replace("${kernelopts}", ko)
            .replace("$kernelopts", ko);
        return normalize_kernel_options(&expanded);
    }
    None
}

fn extract_loader_entry_options(entry: &str, kernel_name: &str) -> Option<String> {
    let mut linux_matches = false;
    let mut options = None;

    for line in entry.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("linux ") {
            let linux_path = rest.split_whitespace().next().unwrap_or_default();
            let linux_base = std::path::Path::new(linux_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(linux_path);
            // Some images use a symlink like "vmlinuz" in loader entries while the extracted
            // kernel file is versioned (or vice-versa). Prefer an exact match, but allow a
            // conservative compatibility match when either side is the common "vmlinuz" alias.
            linux_matches = linux_base == kernel_name
                || (linux_base == "vmlinuz" && kernel_name.starts_with("vmlinuz"))
                || (kernel_name == "vmlinuz" && linux_base.starts_with("vmlinuz"));
        } else if let Some(rest) = trimmed.strip_prefix("options ") {
            options = normalize_kernel_options(rest);
        }
    }

    if linux_matches { options } else { None }
}

fn extract_grub_linux_options(line: &str, kernel_name: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefixes = ["linux ", "linuxefi ", "linux16 "];
    let rest = prefixes
        .iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix))?;

    let mut parts = rest.split_whitespace();
    let kernel_path = parts.next()?;
    let kernel_base = std::path::Path::new(kernel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(kernel_path);
    if kernel_base != kernel_name {
        return None;
    }

    normalize_kernel_options(&parts.collect::<Vec<_>>().join(" "))
}

fn choose_kernel_options(files: &[PathBuf], kernel_name: &str) -> Option<String> {
    let kernelopts = resolve_kernelopts(files);

    let mut loader_entries = files
        .iter()
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("conf"))
        .cloned()
        .collect::<Vec<_>>();
    loader_entries.sort();
    loader_entries.reverse();

    // First pass: find an entry whose "linux" line matches the extracted kernel.
    for path in loader_entries.iter() {
        let content = match fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(options) = extract_loader_entry_options(&content, kernel_name) {
            if let Some(expanded) = expand_kernelopts(&options, kernelopts.as_deref()) {
                return Some(expanded);
            }
            return Some(options);
        }
    }

    // Second pass: if the loader entry does not reference the exact same kernel filename
    // (eg. symlink vs versioned kernel), fall back to the newest *non-rescue* entry that
    // contains a root= argument.
    for path in loader_entries.iter() {
        let content = match fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let lower = content.to_lowercase();
        if lower.contains("rescue") || lower.contains("recovery") || lower.contains("fallback") {
            continue;
        }
        let mut options_line = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("options ") {
                options_line = normalize_kernel_options(rest);
                break;
            }
        }
        if let Some(opts) = options_line {
            if let Some(expanded) = expand_kernelopts(&opts, kernelopts.as_deref())
                && expanded.split_whitespace().any(|t| t.starts_with("root="))
            {
                return Some(expanded);
            }
            if opts.split_whitespace().any(|t| t.starts_with("root=")) {
                return Some(opts);
            }
        }
    }

    let mut grub_cfgs = files
        .iter()
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("cfg"))
        .cloned()
        .collect::<Vec<_>>();
    grub_cfgs.sort();
    grub_cfgs.reverse();

    // First pass: grub.cfg linux line matches the extracted kernel.
    for path in grub_cfgs.iter() {
        let content = match fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for line in content.lines() {
            if let Some(options) = extract_grub_linux_options(line, kernel_name) {
                if let Some(expanded) = expand_kernelopts(&options, kernelopts.as_deref()) {
                    return Some(expanded);
                }
                return Some(options);
            }
        }
    }

    // Second pass: fall back to the first non-rescue linux line that contains a root= argument.
    for path in grub_cfgs.iter() {
        let content = match fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for line in content.lines() {
            let trimmed = line.trim();
            let prefixes = ["linux ", "linuxefi ", "linux16 "];
            let rest = match prefixes.iter().find_map(|p| trimmed.strip_prefix(p)) {
                Some(v) => v,
                None => continue,
            };
            if trimmed.contains("rescue") || trimmed.contains("recovery") {
                continue;
            }
            let parts = rest.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 2 {
                continue;
            }
            if let Some(opts) = normalize_kernel_options(&parts[1..].join(" ")) {
                if let Some(expanded) = expand_kernelopts(&opts, kernelopts.as_deref())
                    && expanded.split_whitespace().any(|t| t.starts_with("root="))
                {
                    return Some(expanded);
                }
                if opts.split_whitespace().any(|t| t.starts_with("root=")) {
                    return Some(opts);
                }
            }
        }
    }

    None
}

fn partition_size_bytes(part: &PartitionSlice) -> u64 {
    part.sectors.saturating_mul(512)
}

async fn has_command(cmd: &str, arg: &str) -> bool {
    tokio::process::Command::new(cmd)
        .arg(arg)
        .output()
        .await
        .is_ok()
}

#[allow(dead_code)]
async fn check_userspace_extract_tools() -> Result<()> {
    for (cmd, arg) in [("qemu-img", "--version"), ("dd", "--version")] {
        tokio::process::Command::new(cmd)
            .arg(arg)
            .output()
            .await
            .with_context(|| format!("could not find {}", cmd))?;
    }

    let have_debugfs = has_command("debugfs", "-V").await;
    let have_mcopy = has_command("mcopy", "-V").await;
    let have_7z = has_command("7z", "i").await;
    anyhow::ensure!(
        have_debugfs || have_mcopy || have_7z,
        "userspace extraction requires debugfs, mcopy, or 7z"
    );
    Ok(())
}

async fn write_partition_image(
    raw_path: &Path,
    image_dir: &Path,
    part: &PartitionSlice,
) -> Result<PathBuf> {
    let part_path = image_dir.join(format!(".extract-part-{}.img", part.number));
    let _ = tokio::fs::remove_file(&part_path).await;

    let output = tokio::process::Command::new("dd")
        .arg(format!("if={}", raw_path.display()))
        .arg(format!("of={}", part_path.display()))
        .arg("bs=512")
        .arg(format!("skip={}", part.start_lba))
        .arg(format!("count={}", part.sectors))
        .arg("status=none")
        .output()
        .await
        .with_context(|| format!("failed to execute dd for partition {}", part.number))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("dd failed for partition {}: {}", part.number, stderr.trim());
    }

    Ok(part_path)
}

async fn dump_partition_subdir_with_mcopy(
    part_path: &Path,
    dump_dir: &Path,
    subdir: &str,
) -> Result<Option<PathBuf>> {
    if !has_command("mcopy", "-V").await {
        return Ok(None);
    }

    let source = match subdir {
        "/" => "::/",
        "/boot" => "::/boot",
        _ => return Ok(None),
    };

    let output = tokio::process::Command::new("mcopy")
        .arg("-s")
        .arg("-n")
        .arg("-i")
        .arg(part_path)
        .arg(source)
        .arg(dump_dir)
        .output()
        .await
        .with_context(|| format!("failed to execute mcopy against {}", part_path.display()))?;

    if !output.status.success() {
        let _ = tokio::fs::remove_dir_all(dump_dir).await;
        return Ok(None);
    }

    Ok(Some(dump_dir.to_path_buf()))
}

async fn dump_partition_subdir_with_7z(
    part_path: &Path,
    dump_dir: &Path,
) -> Result<Option<PathBuf>> {
    if !has_command("7z", "i").await {
        return Ok(None);
    }

    let output = tokio::process::Command::new("7z")
        .arg("x")
        .arg("-y")
        .arg(format!("-o{}", dump_dir.display()))
        .arg(part_path)
        .output()
        .await
        .with_context(|| format!("failed to execute 7z against {}", part_path.display()))?;

    if !output.status.success() {
        let _ = tokio::fs::remove_dir_all(dump_dir).await;
        return Ok(None);
    }

    Ok(Some(dump_dir.to_path_buf()))
}

async fn dump_partition_subdir(
    part_path: &Path,
    image_dir: &Path,
    part: &PartitionSlice,
    subdir: &str,
) -> Result<Option<PathBuf>> {
    let sanitized = if subdir == "/" { "root" } else { "boot" };
    let dump_dir = image_dir.join(format!(".extract-{}-{}", sanitized, part.number));
    let _ = tokio::fs::remove_dir_all(&dump_dir).await;

    tokio::fs::create_dir_all(&dump_dir)
        .await
        .with_context(|| format!("failed to create {}", dump_dir.display()))?;

    if has_command("debugfs", "-V").await {
        let output = tokio::process::Command::new("debugfs")
            .arg("-R")
            .arg(format!("rdump {} {}", subdir, dump_dir.display()))
            .arg(part_path)
            .output()
            .await
            .with_context(|| format!("failed to execute debugfs for partition {}", part.number))?;

        if output.status.success() {
            return Ok(Some(dump_dir));
        }
    }

    if let Some(dir) = dump_partition_subdir_with_mcopy(part_path, &dump_dir, subdir).await? {
        return Ok(Some(dir));
    }

    if let Some(dir) = dump_partition_subdir_with_7z(part_path, &dump_dir).await? {
        return Ok(Some(dir));
    }

    let _ = tokio::fs::remove_dir_all(&dump_dir).await;
    Ok(None)
}

async fn partition_contains_os_release(
    part_path: &Path,
    image_dir: &Path,
    part: &PartitionSlice,
) -> Result<bool> {
    let probe_path = image_dir.join(format!(".extract-os-release-{}", part.number));
    let _ = tokio::fs::remove_file(&probe_path).await;

    let output = tokio::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("dump -p /etc/os-release {}", probe_path.display()))
        .arg(part_path)
        .output()
        .await
        .with_context(|| {
            format!(
                "failed to probe /etc/os-release in partition {}",
                part.number
            )
        })?;

    let exists = output.status.success() && probe_path.exists();
    let _ = tokio::fs::remove_file(&probe_path).await;
    Ok(exists)
}

#[allow(dead_code)]
async fn extract_boot_artifacts_userspace(
    image_dir: &Path,
    file_name: &str,
    distro: Distro,
) -> Result<(PathBuf, PathBuf)> {
    check_userspace_extract_tools().await?;

    let raw_path = image_dir.join(format!("{}.raw", file_name));
    let _ = tokio::fs::remove_file(&raw_path).await;

    let convert = tokio::process::Command::new("qemu-img")
        .arg("convert")
        .arg("-O")
        .arg("raw")
        .arg(file_name)
        .arg(&raw_path)
        .current_dir(image_dir)
        .output()
        .await
        .with_context(|| format!("failed to convert {} to raw", file_name))?;
    if !convert.status.success() {
        let stderr = String::from_utf8_lossy(&convert.stderr);
        bail!("qemu-img convert failed: {}", stderr.trim());
    }

    let parts = list_partitions(&raw_path)?;
    let mut root_hint = None;
    let mut last_err = None;

    for part in &parts {
        let part_path = match write_partition_image(&raw_path, image_dir, part).await {
            Ok(path) => path,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };

        match partition_contains_os_release(&part_path, image_dir, part).await {
            Ok(true) => {
                root_hint = Some(part.number);
            }
            Ok(false) => {}
            Err(err) => {
                last_err = Some(err);
            }
        }

        let _ = tokio::fs::remove_file(&part_path).await;
        if root_hint.is_some() {
            break;
        }
    }

    for part in &parts {
        let part_path = match write_partition_image(&raw_path, image_dir, part).await {
            Ok(path) => path,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };

        let mut dump_candidates = vec![("/boot", false)];
        if partition_size_bytes(part) <= 2 * 1024 * 1024 * 1024 {
            dump_candidates.push(("/", true));
        }

        let mut found = None;
        for (subdir, is_partition_root) in dump_candidates {
            let dump_dir = match dump_partition_subdir(&part_path, image_dir, part, subdir).await {
                Ok(Some(dir)) => dir,
                Ok(None) => continue,
                Err(err) => {
                    last_err = Some(err);
                    continue;
                }
            };

            let files = match collect_files_recursive(&dump_dir) {
                Ok(v) => v,
                Err(err) => {
                    let _ = tokio::fs::remove_dir_all(&dump_dir).await;
                    last_err = Some(err);
                    continue;
                }
            };

            let kernel_src = choose_kernel_file(&files, distro.clone());
            let initrd_src = choose_initrd_file(&files, distro.clone());
            if let (Some(kernel_src), Some(initrd_src)) = (kernel_src, initrd_src) {
                let kernel_name = kernel_src
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();
                let kernel_args = choose_kernel_options(&files, &kernel_name);
                found = Some((
                    dump_dir,
                    kernel_src,
                    initrd_src,
                    is_partition_root,
                    kernel_args,
                ));
                break;
            }

            let _ = tokio::fs::remove_dir_all(&dump_dir).await;
        }

        let Some((dump_dir, kernel_src, initrd_src, is_partition_root, kernel_args)) = found else {
            let _ = tokio::fs::remove_file(&part_path).await;
            continue;
        };

        let kernel_name = kernel_src
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| "invalid kernel filename")?
            .to_string();
        let initrd_name = initrd_src
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| "invalid initrd filename")?
            .to_string();

        let kernel_path = image_dir.join(&kernel_name);
        let initrd_path = image_dir.join(&initrd_name);

        fs::copy(&kernel_src, &kernel_path).with_context(|| {
            format!(
                "failed to copy extracted kernel {} -> {}",
                kernel_src.display(),
                kernel_path.display()
            )
        })?;
        fs::copy(&initrd_src, &initrd_path).with_context(|| {
            format!(
                "failed to copy extracted initrd {} -> {}",
                initrd_src.display(),
                initrd_path.display()
            )
        })?;

        let chosen_root = if is_partition_root {
            root_hint
                .or_else(|| {
                    parts
                        .iter()
                        .find(|candidate| candidate.number != part.number)
                        .map(|candidate| candidate.number)
                })
                .unwrap_or(part.number)
        } else {
            root_hint.unwrap_or(part.number)
        };
        fs::write(root_hint_path(image_dir), chosen_root.to_string()).with_context(|| {
            format!(
                "failed to write root partition hint in {}",
                image_dir.display()
            )
        })?;
        if let Some(args) = kernel_args {
            fs::write(kernel_args_hint_path(image_dir), args).with_context(|| {
                format!(
                    "failed to write kernel args hint in {}",
                    image_dir.display()
                )
            })?;
        }

        let _ = tokio::fs::remove_dir_all(&dump_dir).await;
        let _ = tokio::fs::remove_file(&part_path).await;
        let _ = tokio::fs::remove_file(&raw_path).await;
        return Ok((kernel_path, initrd_path));
    }

    let _ = tokio::fs::remove_file(&raw_path).await;

    if let Some(err) = last_err {
        return Err(err)
            .with_context(|| "userspace qcow2 extraction did not find a usable /boot tree");
    }

    bail!("userspace qcow2 extraction did not find kernel/initrd in any partition");
}

async fn detect_root_arg(image_path: &Path) -> Result<String> {
    let image_dir = image_path.parent().with_context(|| "missing image dir")?;
    let kernel_args_path = kernel_args_hint_path(image_dir);
    if let Ok(args) = fs::read_to_string(&kernel_args_path) {
        let trimmed = args.trim();
        if !trimmed.is_empty() {
            // Some guestfs outputs include a trailing ':' after device names (e.g. /dev/sda3:).
            // Also, some bootloader entries may embed `root=/dev/vda3:`.
            // Sanitize these so direct-kernel boot does not hang waiting for a non-existent device.
            let sanitized = trimmed
                .split_whitespace()
                .map(|t| {
                    if let Some(rest) = t.strip_prefix("root=") {
                        let clean = rest.trim_end_matches(':');
                        format!("root={clean}")
                    } else {
                        t.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            return Ok(sanitized);
        }
    }

    let hint_path = root_hint_path(image_dir);
    if let Ok(hint) = fs::read_to_string(&hint_path)
        && let Ok(part) = hint.trim().parse::<usize>()
    {
        return Ok(format!("root=/dev/vda{}", part));
    }

    let file_name = image_path
        .file_name()
        .and_then(|v| v.to_str())
        .with_context(|| "invalid image filename")?;
    let args = [
        OsStr::new("--ro"),
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new("-i"),
        OsStr::new("mountpoints"),
    ];
    let output = run_guestfs_tool("guestfish", &args, image_dir).await?;
    if !output.status.success() {
        return Ok(default_root_arg());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let mut dev = None;
        if parts[0].starts_with("/dev/") && parts[1] == "/" {
            dev = Some(parts[0]);
        }
        if parts[1].starts_with("/dev/") && parts[0] == "/" {
            dev = Some(parts[1]);
        }
        if let Some(d) = dev {
            // guestfish `mountpoints` typically prints `/dev/sda3: /`.
            let d = d.trim_end_matches(':');
            let virt = if let Some(rest) = d.strip_prefix("/dev/sd") {
                format!("/dev/vd{}", rest)
            } else {
                d.to_string()
            };
            return Ok(format!("root={}", virt));
        }
    }
    Ok(default_root_arg())
}

// ---------------------------------------------------------------------------
// Debian
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Debian {}

impl ImageAction for Debian {
    async fn download(&self, name: &str) -> Result<()> {
        download_remote_image(name, Distro::Debian).await
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        extract_boot_artifacts_guestfs(&image_dir, &file_name, Distro::Debian)
            .await
            .with_context(|| "failed to extract Debian kernel/initrd from qcow2")
    }

    fn distro(&self) -> Distro {
        Distro::Debian
    }
}

// ---------------------------------------------------------------------------
// Ubuntu - downloads the official cloud image and extracts kernel/initrd via libguestfs
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Ubuntu {}

impl ImageAction for Ubuntu {
    async fn download(&self, name: &str) -> Result<()> {
        download_remote_image(name, Distro::Ubuntu).await
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        extract_boot_artifacts_guestfs(&image_dir, &file_name, Distro::Ubuntu)
            .await
            .with_context(|| "failed to extract Ubuntu kernel/initrd from qcow2")
    }

    fn distro(&self) -> Distro {
        Distro::Ubuntu
    }
}

// ---------------------------------------------------------------------------
// Fedora - uses the official cloud image and extracts kernel/initrd via libguestfs
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Fedora {}

impl ImageAction for Fedora {
    async fn download(&self, name: &str) -> Result<()> {
        download_remote_image(name, Distro::Fedora).await
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        extract_boot_artifacts_guestfs(&image_dir, &file_name, Distro::Fedora)
            .await
            .with_context(|| "failed to extract Fedora kernel/initrd from qcow2")
    }

    fn distro(&self) -> Distro {
        Distro::Fedora
    }
}

// ---------------------------------------------------------------------------
// Arch - uses the official cloud image and extracts kernel/initrd via libguestfs
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Arch {}

impl ImageAction for Arch {
    async fn download(&self, name: &str) -> Result<()> {
        download_remote_image(name, Distro::Arch).await
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        extract_boot_artifacts_guestfs(&image_dir, &file_name, Distro::Arch)
            .await
            .with_context(|| "failed to extract Arch kernel/initrd from qcow2")
    }

    fn distro(&self) -> Distro {
        Distro::Arch
    }
}

// ---------------------------------------------------------------------------
// Custom - user-provided image with flexible configuration
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Custom {
    pub config: CustomImageConfig,
}

impl Custom {
    pub fn new(config: CustomImageConfig) -> Self {
        Custom { config }
    }
}

impl ImageAction for Custom {
    async fn download(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Download main image file
        let image_path = image_dir.join(format!("{}.qcow2", name));
        materialize_source_with_hash(
            &self.config.image_source,
            &image_path,
            &self.config.image_hash,
            self.config.image_hash_type.clone(),
        )
        .await?;

        // Download kernel if provided
        if let (Some(kernel_src), Some(kernel_hash)) =
            (&self.config.kernel_source, &self.config.kernel_hash)
        {
            let kernel_path = image_dir.join("vmlinuz");
            materialize_source_with_hash(
                kernel_src,
                &kernel_path,
                kernel_hash,
                self.config.image_hash_type.clone(),
            )
            .await?;
        }

        // Download initrd if provided
        if let (Some(initrd_src), Some(initrd_hash)) =
            (&self.config.initrd_source, &self.config.initrd_hash)
        {
            let initrd_path = image_dir.join("initrd.img");
            materialize_source_with_hash(
                initrd_src,
                &initrd_path,
                initrd_hash,
                self.config.image_hash_type.clone(),
            )
            .await?;
        }

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let kernel_path = image_dir.join("vmlinuz");
        let initrd_path = image_dir.join("initrd.img");
        if kernel_path.exists() && initrd_path.exists() {
            debug!("Using pre-provided kernel and initrd files");
            return Ok((kernel_path, initrd_path));
        }

        ensure_extraction_prerequisites().await?;
        let file_name = format!("{}.qcow2", name);
        let boot_files = guestfish_ls_boot(&image_dir, &file_name).await?;

        let mut kernel_name = None;
        let mut initrd_name = None;
        for line in boot_files.lines() {
            let file = line.trim();
            if kernel_name.is_none() && (file.starts_with("vmlinuz") || file.starts_with("bzImage"))
            {
                kernel_name = Some(file.to_string());
            }
            if initrd_name.is_none()
                && (file.starts_with("initrd") || file.starts_with("initramfs"))
            {
                initrd_name = Some(file.to_string());
            }
        }

        let kernel = kernel_name.with_context(|| "failed to find kernel file in /boot")?;
        let initrd = initrd_name.with_context(|| "failed to find initrd file in /boot")?;

        let kernel_src = format!("/boot/{}", kernel);
        virt_copy_out(&image_dir, &file_name, &kernel_src, "kernel").await?;
        let initrd_src = format!("/boot/{}", initrd);
        virt_copy_out(&image_dir, &file_name, &initrd_src, "initrd").await?;

        Ok((image_dir.join(&kernel), image_dir.join(&initrd)))
    }

    fn distro(&self) -> Distro {
        Distro::Custom
    }
}

// Helper function to download a file
// ---------------------------------------------------------------------------
// Image wrapper enum
// ---------------------------------------------------------------------------

/// Wrapper enum for different Image types
#[derive(Debug)]
pub enum Image {
    Debian(ImageMeta<Debian>),
    Ubuntu(ImageMeta<Ubuntu>),
    Fedora(ImageMeta<Fedora>),
    Arch(ImageMeta<Arch>),
    Custom(ImageMeta<Custom>),
}

impl Image {
    /// Get the underlying name regardless of distro
    pub fn name(&self) -> &str {
        match self {
            Image::Debian(img) => &img.name,
            Image::Ubuntu(img) => &img.name,
            Image::Fedora(img) => &img.name,
            Image::Arch(img) => &img.name,
            Image::Custom(img) => &img.name,
        }
    }

    /// Get the underlying image path regardless of distro
    pub fn path(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.path,
            Image::Ubuntu(img) => &img.path,
            Image::Fedora(img) => &img.path,
            Image::Arch(img) => &img.path,
            Image::Custom(img) => &img.path,
        }
    }

    /// Get the kernel path regardless of distro
    pub fn kernel(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.kernel,
            Image::Ubuntu(img) => &img.kernel,
            Image::Fedora(img) => &img.kernel,
            Image::Arch(img) => &img.kernel,
            Image::Custom(img) => &img.kernel,
        }
    }

    /// Get the initrd path regardless of distro
    pub fn initrd(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.initrd,
            Image::Ubuntu(img) => &img.initrd,
            Image::Fedora(img) => &img.initrd,
            Image::Arch(img) => &img.initrd,
            Image::Custom(img) => &img.initrd,
        }
    }

    pub fn root_arg(&self) -> &str {
        match self {
            Image::Debian(img) => &img.root_arg,
            Image::Ubuntu(img) => &img.root_arg,
            Image::Fedora(img) => &img.root_arg,
            Image::Arch(img) => &img.root_arg,
            Image::Custom(img) => &img.root_arg,
        }
    }

    pub fn prefer_direct_kernel_boot(&self) -> bool {
        true
    }
}

/// Factory function to create Image instances based on distro
pub async fn create_image(distro: Distro, name: &str) -> Result<Image> {
    match distro {
        Distro::Debian => {
            let image = ImageMeta::<Debian>::create(name).await?;
            Ok(Image::Debian(image))
        }
        Distro::Ubuntu => {
            let image = ImageMeta::<Ubuntu>::create(name).await?;
            Ok(Image::Ubuntu(image))
        }
        Distro::Fedora => {
            let image = ImageMeta::<Fedora>::create(name).await?;
            Ok(Image::Fedora(image))
        }
        Distro::Arch => {
            let image = ImageMeta::<Arch>::create(name).await?;
            Ok(Image::Arch(image))
        }
        Distro::Custom => {
            bail!("use create_custom_image() for custom images");
        }
    }
}

/// Factory function for custom images
pub async fn create_custom_image(name: &str, config: CustomImageConfig) -> Result<Image> {
    let action = Custom::new(config);
    let image = ImageMeta::create_with_action(name, action).await?;
    Ok(Image::Custom(image))
}

/// Calculate SHA256 with command line tool `sha256sum`
pub async fn get_sha256(path: &PathBuf) -> Result<String> {
    let output = tokio::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .await
        .with_context(|| format!("failed to execute sha256sum on {}", path.display()))?;

    if !output.status.success() {
        bail!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha256 = stdout
        .split_whitespace()
        .next()
        .with_context(|| "failed to parse sha256sum output")?
        .to_string();

    Ok(sha256)
}

/// Calculate SHA512 with command line tool `sha512sum`
pub async fn get_sha512(path: &PathBuf) -> Result<String> {
    let output = tokio::process::Command::new("sha512sum")
        .arg(path)
        .output()
        .await
        .with_context(|| format!("failed to execute sha512sum on {}", path.display()))?;

    if !output.status.success() {
        bail!(
            "sha512sum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha512 = stdout
        .split_whitespace()
        .next()
        .with_context(|| "failed to parse sha512sum output")?
        .to_string();

    Ok(sha512)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn test_subscriber_init() {
        // Keep test logging setup local to this module to avoid coupling
        // image unit tests to integration-test helpers.
        use std::sync::Once;
        use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

        static INIT: Once = Once::new();
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_timer(LocalTime::rfc_3339())
                .try_init()
                .ok();
        });
    }

    #[test]
    fn test_find_hash_for_exact_filename() {
        let checksums = "\
748f52b959f63352e1e121508cedeae2e66d3e90be00e6420a0b8b9f14a0f84dc54ed801fb5be327866876268b808543465b1613c8649efeeb5f987ff9df1549  debian-13-generic-amd64.json
\
f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65  debian-13-generic-amd64.qcow2";
        let result = find_hash_for_file(checksums, "debian-13-generic-amd64.qcow2");
        assert_eq!(
            result,
            Some("f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65".to_string())
        );
    }

    #[test]
    fn test_custom_image_config_serde() {
        let config = CustomImageConfig {
            image_source: ImageSource::Url("https://example.com/image.qcow2".to_string()),
            image_hash: "abcdef123456".to_string(),
            image_hash_type: ShaType::Sha256,
            kernel_source: Some(ImageSource::Url("https://example.com/vmlinuz".to_string())),
            kernel_hash: Some("kernel123".to_string()),
            initrd_source: Some(ImageSource::Url("https://example.com/initrd".to_string())),
            initrd_hash: Some("initrd456".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let decoded: CustomImageConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, config);
    }

    #[test]
    fn test_image_sources_config_toml_parse() {
        let config: ImageSourcesConfig = toml::from_str(
            r#"
[debian]
image_url = "https://example.com/debian.qcow2"
checksum_url = "https://example.com/SHA512SUMS"
checksum_entry = "debian.qcow2"
checksum_type = "Sha512"

[ubuntu]
image_url = "https://example.com/ubuntu.img"
checksum_url = "https://example.com/SHA256SUMS"
checksum_entry = "ubuntu.img"
checksum_type = "Sha256"

[fedora]
image_url = "https://example.com/fedora.qcow2"
checksum_url = "https://example.com/CHECKSUM"
checksum_entry = "fedora.qcow2"
checksum_type = "Sha256"

[arch]
image_url = "https://example.com/arch.qcow2"
checksum_url = "https://example.com/arch.SHA256"
checksum_entry = "arch.qcow2"
checksum_type = "Sha256"
"#,
        )
        .unwrap();

        assert_eq!(config.debian.checksum_type, ShaType::Sha512);
        assert_eq!(config.ubuntu.checksum_entry, "ubuntu.img");
        assert_eq!(config.fedora.image_url, "https://example.com/fedora.qcow2");
        assert_eq!(config.arch.checksum_url, "https://example.com/arch.SHA256");
    }

    #[test]
    fn test_find_hash_for_file_formats() {
        // Format 1: "<hex>  <filename>"
        let f1 = "abc123  foo.bin\n012345  bar.bin";
        assert_eq!(
            find_hash_for_file(f1, "bar.bin"),
            Some("012345".to_string())
        );

        // Format 2: "SHA256 (<filename>) = <hex>"
        let f2 = "SHA256 (image.qcow2) = deadbeef\nSHA256 (other) = 00";
        assert_eq!(
            find_hash_for_file(f2, "image.qcow2"),
            Some("deadbeef".to_string())
        );

        // Format 2: SHA512 variant
        let f3 = "SHA512 (k) = aaa\nSHA512 (initrd.img) = bbb";
        assert_eq!(
            find_hash_for_file(f3, "initrd.img"),
            Some("bbb".to_string())
        );
    }

    #[tokio::test]
    async fn test_streaming_sha256_empty_file() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path();

        let hash = compute_sha256_streaming(path).await?;

        // SHA-256 of empty file
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_streaming_vs_shell_sha256() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            f.write_all(b"streaming hash test data")?;
        }

        let shell = get_sha256(&path).await?;
        let stream = compute_sha256_streaming(&path).await?;

        assert_eq!(shell, stream, "streaming must match shell");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_streaming_vs_shell_sha512() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            f.write_all(b"streaming hash test data")?;
        }

        let shell = get_sha512(&path).await?;
        let stream = compute_sha512_streaming(&path).await?;

        assert_eq!(shell, stream, "streaming must match shell");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_custom_image_nonexistent_local_path() -> Result<()> {
        test_subscriber_init();

        let config = CustomImageConfig {
            image_source: ImageSource::LocalPath(PathBuf::from("/nonexistent/image.qcow2")),
            image_hash: "fakehash".to_string(),
            image_hash_type: ShaType::Sha256,
            kernel_source: None,
            kernel_hash: None,
            initrd_source: None,
            initrd_hash: None,
        };

        let result = create_custom_image("test-nonexistent", config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_custom_image_hash_mismatch() -> Result<()> {
        test_subscriber_init();

        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            f.write_all(b"test content")?;
        }

        let config = CustomImageConfig {
            image_source: ImageSource::LocalPath(path),
            image_hash: "wronghash123".to_string(),
            image_hash_type: ShaType::Sha256,
            kernel_source: None,
            kernel_hash: None,
            initrd_source: None,
            initrd_hash: None,
        };

        let result = create_custom_image("test-hash-mismatch", config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));

        Ok(())
    }
}
