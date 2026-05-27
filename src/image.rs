use std::{
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use indicatif::{ProgressState, ProgressStyle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::{Span, info, info_span};
use tracing_indicatif::span_ext::IndicatifSpanExt;

use crate::utils::{QleanDirs, qlean_user_agent};

/// Virtual machine image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    name: String,
    path: PathBuf,
    arch: GuestArch,
    distro: Distro,
    pub(crate) digest: (ShaType, String),
    #[serde(default)]
    pub(crate) clear: bool,
}

/// Distribution of the image: Debian, Ubuntu, Fedora or Arch.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Default)]
pub enum Distro {
    #[default]
    Debian,
    Ubuntu,
    Fedora,
    Arch,
}

/// Guest architecture: amd64, aarch64 or riscv64.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Default)]
pub enum GuestArch {
    #[default]
    Amd64,
    Aarch64,
    Riscv64,
}

/// Type of hash: SHA256 or SHA512.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub(crate) enum ShaType {
    Sha256,
    Sha512,
}

/// Source of a image: URL or local file path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum ImageSource {
    Url(String),
    LocalPath(PathBuf),
}

impl Default for ImageSource {
    fn default() -> Self {
        ImageSource::Url(String::new())
    }
}

/// Configuration for a virtual machine image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ImageConfig {
    /// Architecture of the image, defaults to `GuestArch::Amd64`.
    pub arch: GuestArch,
    /// Distribution of the image, defaults to `Distro::Debian`.
    pub distro: Distro,
    /// Source of the image, it can be a URL or a local file path. If provided, the image will be fetched from the source and verified against the digest.
    pub source: Option<String>,
    /// Digest of the image, in the form of `sha256:<hex>` or `sha512:<hex>`. It should be provided along with the source.
    pub digest: Option<String>,
    /// Whether to clear the image after use, defaults to `false`. It is useful for custom images that are not expected to be used again.
    pub clear: bool,
}

impl ImageConfig {
    /// Set the distribution of the image.
    pub fn with_distro(self, distro: Distro) -> Self {
        Self { distro, ..self }
    }

    /// Set the architecture of the image.
    pub fn with_arch(self, arch: GuestArch) -> Self {
        Self { arch, ..self }
    }

    /// Set the source of the image.
    pub fn with_source(self, source: String) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Set the digest of the image.
    pub fn with_digest(self, digest: String) -> Self {
        Self {
            digest: Some(digest),
            ..self
        }
    }

    /// Set whether to clear the image after use.
    pub fn with_clear(self, clear: bool) -> Self {
        Self { clear, ..self }
    }

    /// `source` and `digest` must both be set or both omitted.
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (self.source.is_none() && self.digest.is_none())
                || (self.source.is_some() && self.digest.is_some()),
            "source and digest must both be set or both omitted"
        );
        Ok(())
    }
}

impl AsRef<ImageConfig> for ImageConfig {
    fn as_ref(&self) -> &ImageConfig {
        self
    }
}

fn image_cache_name(
    distro: Distro,
    arch: GuestArch,
    override_source: &Option<ImageSource>,
) -> Result<String> {
    if let Some(src) = override_source {
        return Ok(cache_name_from_source(src));
    }
    let spec = builtin_remote_image(distro, arch)?;
    Ok(stem_from_filename(spec.checksum_entry))
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

/// Strip PGP armor wrapper (e.g. Fedora `*-CHECKSUM`) so line-oriented parsers see only the payload.
fn checksum_text_payload(raw: &str) -> &str {
    let marker = "-----BEGIN PGP SIGNED MESSAGE-----";
    let Some(idx) = raw.find(marker) else {
        return raw;
    };
    let after = &raw[idx + marker.len()..];
    let body_start = after.find("\n\n").map(|i| i + 2).unwrap_or(0);
    let mut body = &after[body_start..];
    if let Some(sig) = body.find("-----BEGIN PGP SIGNATURE-----") {
        body = &body[..sig];
    }
    body
}

/// Parse a checksum file and return the hash for a given filename.
///
/// Supports common formats:
/// 1) "<hex>  <filename>" (including "*filename" and "./filename"), one pair per line
/// 2) "SHA256 (<filename>) = <hex>" / "SHA512 (<filename>) = <hex>"
///
/// Comment lines (`#` ...) and PGP-signed-message wrappers are ignored.
fn find_hash_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    let payload = checksum_text_payload(checksums_text);

    for line in payload.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(first) = parts.next() else { continue };
        // Format: SHA256 (name) = hex
        for prefix in ["SHA256 (", "SHA512 ("] {
            if let Some(rest) = line.strip_prefix(prefix)
                && let Some((entry_name, hash_part)) = rest.split_once(") = ")
                && checksum_name_matches(entry_name, filename)
            {
                return Some(hash_part.trim().to_string());
            }
        }
        let Some(second) = parts.next() else { continue };
        if first.starts_with("SHA256(") || first.starts_with("SHA512(") {
            continue;
        }
        if checksum_name_matches(second, filename) {
            return Some(first.to_string());
        }
    }

    None
}

/// Built-in official cloud image locations (pin versions by editing this module).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteImageSpec {
    image_url: &'static str,
    checksum_url: &'static str,
    checksum_entry: &'static str,
    checksum_type: ShaType,
}

fn builtin_remote_image(distro: Distro, arch: GuestArch) -> Result<RemoteImageSpec> {
    match arch {
        GuestArch::Amd64 => match distro {
            Distro::Debian => Ok(RemoteImageSpec {
                image_url: "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
                checksum_url: "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS",
                checksum_entry: "debian-13-generic-amd64.qcow2",
                checksum_type: ShaType::Sha512,
            }),
            Distro::Ubuntu => Ok(RemoteImageSpec {
                image_url: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
                checksum_url: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS",
                checksum_entry: "noble-server-cloudimg-amd64.img",
                checksum_type: ShaType::Sha256,
            }),
            Distro::Fedora => Ok(RemoteImageSpec {
                image_url: "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2",
                checksum_url: "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-43-1.6-x86_64-CHECKSUM",
                checksum_entry: "Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2",
                checksum_type: ShaType::Sha256,
            }),
            Distro::Arch => Ok(RemoteImageSpec {
                image_url: "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
                checksum_url: "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256",
                checksum_entry: "Arch-Linux-x86_64-cloudimg.qcow2",
                checksum_type: ShaType::Sha256,
            }),
        },
        GuestArch::Aarch64 => {
            bail!(
                "builtin image specs are currently only available for amd64, got {:?}",
                arch
            );
        }
        GuestArch::Riscv64 => {
            bail!(
                "builtin image specs are currently only available for amd64, got {:?}",
                arch
            );
        }
    }
}

async fn fetch_text(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(qlean_user_agent())
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

async fn fetch_expected_hash(spec: &RemoteImageSpec) -> Result<String> {
    let checksums_text = fetch_text(spec.checksum_url)
        .await
        .with_context(|| format!("failed to fetch checksum file from {}", spec.checksum_url))?;

    find_hash_for_file(&checksums_text, spec.checksum_entry).with_context(|| {
        format!(
            "checksum file {} did not contain an entry for {}",
            spec.checksum_url, spec.checksum_entry
        )
    })
}

fn stem_from_filename(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name)
        .to_string()
}

fn parse_prefixed_digest(s: &str) -> Result<(ShaType, String)> {
    let (algo, hex) = s
        .split_once(':')
        .with_context(|| "digest must be in the form sha256:<hex> or sha512:<hex>")?;
    let sha_type = match algo.trim().to_ascii_lowercase().as_str() {
        "sha256" => ShaType::Sha256,
        "sha512" => ShaType::Sha512,
        _ => bail!("unsupported digest algorithm prefix: {}", algo),
    };
    let body = hex.trim();
    anyhow::ensure!(!body.is_empty(), "digest body cannot be empty");
    anyhow::ensure!(
        body.chars().all(|c| c.is_ascii_hexdigit()),
        "digest body must be hexadecimal"
    );
    Ok((sha_type, body.to_string()))
}

fn resolve_image_source(source: &str) -> ImageSource {
    let s = source.trim();
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("file://")
    {
        ImageSource::Url(s.to_string())
    } else {
        ImageSource::LocalPath(PathBuf::from(s))
    }
}

fn cache_name_from_source(source: &ImageSource) -> String {
    match source {
        ImageSource::Url(url) => {
            let last = url.rsplit('/').next().unwrap_or("custom-image.qcow2");
            stem_from_filename(last)
        }
        ImageSource::LocalPath(path) => {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("custom-image.qcow2");
            stem_from_filename(name)
        }
    }
}

enum StreamingHasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl StreamingHasher {
    fn new(kind: &ShaType) -> Self {
        match kind {
            ShaType::Sha256 => Self::Sha256(Sha256::new()),
            ShaType::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    fn finalize_hex(self) -> String {
        // `sha2` 0.11 returns `hybrid_array::Array<u8, _>` from `Digest::finalize`,
        // which no longer implements `LowerHex` (the 0.10-era `GenericArray` did).
        // It still implements `AsRef<[u8]>`, so `hex::encode` is the canonical
        // replacement and matches what RustCrypto's own examples now use.
        match self {
            Self::Sha256(h) => hex::encode(h.finalize()),
            Self::Sha512(h) => hex::encode(h.finalize()),
        }
    }
}

/// Compute a streaming hash over `path` using sync I/O on a blocking thread.
async fn compute_hash(path: &Path, hash_type: ShaType) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = BufReader::with_capacity(
            1024 * 1024,
            std::fs::File::open(&path)
                .with_context(|| format!("failed to open {}", path.display()))?,
        );

        let mut buf = vec![0u8; 64 * 1024];
        let mut hasher = StreamingHasher::new(&hash_type);
        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| "failed to read file during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(hasher.finalize_hex())
    })
    .await
    .with_context(|| "hash computation task failed")?
}

/// Copy a file to `dest` while computing a streaming hash using buffered sync I/O.
fn copy_with_hash(src: &Path, dest: &Path, hash_type: &ShaType) -> Result<String> {
    let mut src_f = BufReader::with_capacity(
        1024 * 1024,
        std::fs::File::open(src).with_context(|| format!("failed to open {}", src.display()))?,
    );
    let mut dst_f = BufWriter::with_capacity(
        1024 * 1024,
        std::fs::File::create(dest)
            .with_context(|| format!("failed to create {}", dest.display()))?,
    );

    let mut buf = vec![0u8; 64 * 1024];
    let mut hasher = StreamingHasher::new(hash_type);
    loop {
        let n = src_f
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", src.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        dst_f
            .write_all(&buf[..n])
            .with_context(|| format!("failed to write {}", dest.display()))?;
    }
    dst_f
        .flush()
        .with_context(|| format!("failed to flush {}", dest.display()))?;

    Ok(hasher.finalize_hex())
}

/// Download a remote file and compute its hash streamingly in a single pass.
async fn download_with_hash(url: &str, dest_path: &PathBuf, hash_type: ShaType) -> Result<String> {
    let tmp_path = dest_path.with_extension("part");

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(20))
        .user_agent(qlean_user_agent())
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

    let download_span = info_span!("http_download", url = %url);

    let style_known = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
    )
    .unwrap()
    .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
        let _ = std::fmt::write(w, format_args!("{:.1}s", state.eta().as_secs_f64()));
    })
    .progress_chars("#>-");

    let style_unknown = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] {bytes} ({bytes_per_sec}) {msg}",
    )
    .unwrap();

    if let Some(total) = total_size {
        download_span.pb_set_style(&style_known);
        download_span.pb_set_length(total);
    } else {
        download_span.pb_set_style(&style_unknown);
        download_span.pb_set_length(u64::MAX);
    }
    download_span.pb_set_message("downloading");

    let _download_enter = download_span.enter();

    let mut hasher = StreamingHasher::new(&hash_type);
    loop {
        let next = tokio::time::timeout(idle, stream.next())
            .await
            .with_context(|| format!("download stalled for {} (>{:?} without data)", url, idle))?;
        let Some(chunk) = next else { break };
        let chunk = chunk.with_context(|| "failed to read chunk")?;
        downloaded += chunk.len() as u64;
        Span::current().pb_set_position(downloaded);
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .with_context(|| "failed to write chunk")?;
    }

    let hash = hasher.finalize_hex();

    download_span.pb_set_finish_message(&format!("{} MiB downloaded", downloaded / (1024 * 1024)));
    std::mem::drop(_download_enter);

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

    info!("Download completed");
    Ok(hash)
}

/// Fetch image file from remote source or local path and verify it against the expected hash.
async fn fetch_from_source(
    source: &ImageSource,
    dest: &PathBuf,
    expected_hash: &str,
    hash_type: ShaType,
) -> Result<()> {
    match source {
        ImageSource::Url(url) => {
            let computed = download_with_hash(url, dest, hash_type.clone()).await?;
            anyhow::ensure!(
                computed.eq_ignore_ascii_case(expected_hash),
                "hash mismatch: expected {}, got {}",
                expected_hash,
                computed
            );
        }
        ImageSource::LocalPath(src) => {
            anyhow::ensure!(src.exists(), "file does not exist: {}", src.display());
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("failed to create dir {}", parent.display()))?;
            }

            let src_path = src.clone();
            let dest_path = dest.clone();
            let computed = tokio::task::spawn_blocking(move || {
                copy_with_hash(&src_path, &dest_path, &hash_type)
            })
            .await
            .with_context(|| "copy/hash task failed")??;

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

impl Image {
    pub(crate) fn path(&self) -> &PathBuf {
        &self.path
    }

    pub(crate) fn guest_arch(&self) -> GuestArch {
        self.arch
    }
}

impl Image {
    /// Create a new image with specified configuration.
    pub async fn new<C: AsRef<ImageConfig>>(config: C) -> Result<Self> {
        let config = config.as_ref();
        config.validate().context("invalid image config")?;

        let override_source = config.source.as_deref().map(resolve_image_source);
        let override_digest = config
            .digest
            .as_deref()
            .map(parse_prefixed_digest)
            .transpose()?;

        let name = image_cache_name(config.distro, config.arch, &override_source)?;

        if let Ok(image) = Self::load(&name).await {
            return Ok(image);
        }

        let dirs = QleanDirs::new()?;
        let image_path = dirs.images.join(format!("{}.qcow2", name));
        let image_digest: (ShaType, String);

        if let (Some(src), Some((digest_type, digest_hex))) = (override_source, override_digest) {
            // If source and digest are provided, fetch from source.
            fetch_from_source(&src, &image_path, &digest_hex, digest_type.clone()).await?;

            image_digest = (digest_type, digest_hex);
        } else {
            // Otherwise, fetch from builtin remote image.
            let spec = builtin_remote_image(config.distro, config.arch)?;
            let expected_hash = fetch_expected_hash(&spec).await?;

            fetch_from_source(
                &ImageSource::Url(spec.image_url.to_string()),
                &image_path,
                &expected_hash,
                spec.checksum_type.clone(),
            )
            .await?;

            image_digest = (spec.checksum_type, expected_hash);
        }

        let image = Image {
            name: name.to_string(),
            path: image_path,
            arch: config.arch,
            distro: config.distro,
            digest: image_digest,
            clear: config.clear,
        };

        if !config.clear {
            image.save(&name).await?;
        }

        Ok(image)
    }

    /// Load image metadata from disk and validate checksums
    async fn load(name: &str) -> Result<Self> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = tokio::fs::read_to_string(&json_path)
            .await
            .with_context(|| format!("failed to read config file at {}", json_path.display()))?;

        let image: Image = serde_json::from_str(&json_content)
            .with_context(|| format!("failed to parse JSON from {}", json_path.display()))?;

        info!("🔍 Validating cached image");
        let computed = compute_hash(&image.path, image.digest.0.clone()).await?;
        anyhow::ensure!(
            computed.eq_ignore_ascii_case(&image.digest.1),
            "hash mismatch: expected {}, got {}",
            image.digest.1,
            computed
        );

        Ok(image)
    }

    /// Save image metadata to disk using streaming hash.
    async fn save(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = serde_json::to_string_pretty(&self)
            .with_context(|| "failed to serialize image config to JSON")?;

        tokio::fs::write(&json_path, json_content)
            .await
            .with_context(|| format!("failed to write image config to {}", json_path.display()))?;

        Ok(())
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        if self.clear {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Calculate SHA256 with command line tool `sha256sum`
    async fn get_sha256(path: &PathBuf) -> Result<String> {
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
    async fn get_sha512(path: &PathBuf) -> Result<String> {
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
    fn test_image_config_serde() {
        let config = ImageConfig {
            arch: GuestArch::Amd64,
            distro: Distro::Debian,
            source: Some("https://example.com/image.qcow2".to_string()),
            digest: Some("sha256:abcdef123456".to_string()),
            clear: false,
        };

        let json = serde_json::to_string(&config).unwrap();
        let decoded: ImageConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, config);
    }

    #[test]
    fn test_builtin_remote_image_specs() {
        let d = builtin_remote_image(Distro::Debian, GuestArch::Amd64).unwrap();
        assert!(d.image_url.contains("debian-13-generic-amd64.qcow2"));
        assert_eq!(d.checksum_type, ShaType::Sha512);
        assert_eq!(d.checksum_entry, "debian-13-generic-amd64.qcow2");

        assert!(builtin_remote_image(Distro::Debian, GuestArch::Aarch64).is_err());
    }

    #[test]
    fn test_parse_prefixed_digest_case_insensitive() {
        let (algo, hex) = parse_prefixed_digest("SHA512:AbCd").unwrap();
        assert_eq!(algo, ShaType::Sha512);
        assert_eq!(hex, "AbCd");

        assert!(parse_prefixed_digest("md5:abcd").is_err());
    }

    #[test]
    fn test_find_hash_for_file_fedora_pgp_signed_checksum() {
        let checksums = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# Fedora Cloud image
deadbeef00112233 *Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2
other000000000000 *other.img
-----BEGIN PGP SIGNATURE-----
dummy
-----END PGP SIGNATURE-----";
        assert_eq!(
            find_hash_for_file(checksums, "Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2"),
            Some("deadbeef00112233".to_string())
        );
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

        let hash = compute_hash(path, ShaType::Sha256).await?;

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
        let stream = compute_hash(&path, ShaType::Sha256).await?;

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
        let stream = compute_hash(&path, ShaType::Sha512).await?;

        assert_eq!(shell, stream, "streaming must match shell");

        Ok(())
    }
}
