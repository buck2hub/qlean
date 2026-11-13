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
    #[serde(default)]
    pub(crate) guest_os: GuestOs,
    pub(crate) digest: (ShaType, String),
    #[serde(default)]
    pub(crate) clear: bool,
}

/// Guest operating system family.
///
/// Defaults to [`GuestOs::Linux`] so that configs and cached image metadata written
/// before the field existed keep their previous meaning.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Default)]
pub enum GuestOs {
    /// Linux cloud images (the built-in catalog, cloud-init deployment).
    #[default]
    Linux,
    /// Windows images. Requires an explicit `source` + `digest` and `GuestArch::Amd64`.
    Windows,
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
    /// Guest operating system family, defaults to `GuestOs::Linux`.
    ///
    /// `GuestOs::Windows` requires `arch = GuestArch::Amd64`, `source` and `digest`;
    /// `distro` is ignored for Windows images.
    #[serde(default)]
    pub guest_os: GuestOs,
    /// Architecture of the image, defaults to `GuestArch::Amd64`.
    pub arch: GuestArch,
    /// Distribution of the image, defaults to `Distro::Debian`.
    pub distro: Distro,
    /// Source of the image, it can be a URL or a local file path.
    ///
    /// `source` and `digest` must both be set or both omitted: an image is never fetched
    /// without a digest to verify it against, and config validation refuses the half-set
    /// pair with that sentence. When set, the image is fetched from `source` and verified
    /// against `digest`.
    pub source: Option<String>,
    /// Digest of the image, in the form of `sha256:<hex>` or `sha512:<hex>`.
    ///
    /// It must be set together with `source`; see [`ImageConfig::source`] for the rule and
    /// the error a half-set pair produces.
    pub digest: Option<String>,
    /// Whether to clear the image after use, defaults to `false`. It is useful for custom images that are not expected to be used again.
    pub clear: bool,
}

impl ImageConfig {
    /// Set the guest operating system family, defaults to [`GuestOs::Linux`].
    pub fn with_guest_os(self, guest_os: GuestOs) -> Self {
        Self { guest_os, ..self }
    }

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
    ///
    /// Windows guests additionally require an explicit `source` + `digest` and the
    /// amd64 architecture: there is no built-in Windows image catalog, so an implicit
    /// catalog lookup would silently fall back to a Linux cloud image.
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            (self.source.is_none() && self.digest.is_none())
                || (self.source.is_some() && self.digest.is_some()),
            "source and digest must both be set or both omitted"
        );
        if self.guest_os == GuestOs::Windows {
            anyhow::ensure!(
                self.arch == GuestArch::Amd64,
                "guest_os=Windows only supports amd64 guests, got {:?}",
                self.arch
            );
            anyhow::ensure!(
                self.source.is_some() && self.digest.is_some(),
                "guest_os=Windows requires an explicit `source` and `digest`: \
                 the built-in image catalog only provides Linux cloud images"
            );
        }
        Ok(())
    }
}

impl AsRef<ImageConfig> for ImageConfig {
    fn as_ref(&self) -> &ImageConfig {
        self
    }
}

fn image_cache_name(
    guest_os: GuestOs,
    distro: Distro,
    arch: GuestArch,
    override_source: &Option<ImageSource>,
    override_digest: Option<&(ShaType, String)>,
) -> Result<String> {
    let base = cache_name_base(distro, arch, override_source, override_digest)?;
    // Windows images are namespaced so that a Windows qcow2 and a Linux image that
    // happen to share a source filename or digest never share a cache slot.
    Ok(match guest_os {
        GuestOs::Linux => base,
        GuestOs::Windows => format!("{WINDOWS_CACHE_PREFIX}{base}"),
    })
}

/// Prefix applied to Windows image cache entries; keeps Linux cache names unchanged.
const WINDOWS_CACHE_PREFIX: &str = "windows-";

/// Reject a cached image whose recorded guest OS does not match the request.
fn ensure_cached_guest_os(name: &str, requested: GuestOs, cached: GuestOs) -> Result<()> {
    anyhow::ensure!(
        requested == cached,
        "cached image {} belongs to guest OS {:?}, but {:?} was requested; \
         remove the cached image or use a different source/digest",
        name,
        cached,
        requested
    );
    Ok(())
}

fn cache_name_base(
    distro: Distro,
    arch: GuestArch,
    override_source: &Option<ImageSource>,
    override_digest: Option<&(ShaType, String)>,
) -> Result<String> {
    // Prefer digest so catalog images that share a filename (e.g. debian-13-buck2.qcow2
    // behind rotating presigned URLs) never collide across toolchain versions.
    if let Some((sha_type, hex)) = override_digest {
        let prefix = match sha_type {
            ShaType::Sha256 => "sha256",
            ShaType::Sha512 => "sha512",
        };
        return Ok(format!("{prefix}-{hex}"));
    }
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
    // A digest of the wrong length can never match the computed one, and the resulting
    // error would say "digest mismatch" — pointing at the image (corrupt?) instead of at
    // the truncated or half-pasted digest the user actually passed.
    let expected = match sha_type {
        ShaType::Sha256 => 64,
        ShaType::Sha512 => 128,
    };
    anyhow::ensure!(
        body.len() == expected,
        "{} digest must be {expected} hexadecimal characters, got {} (`{}`)",
        algo.trim().to_ascii_lowercase(),
        body.len(),
        if body.len() > 16 {
            format!("{}...", &body[..16])
        } else {
            body.to_string()
        }
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
            // Strip query/fragment so presigned URLs share a stable path stem when
            // no digest is supplied. Prefer digest-keyed names when available.
            let path = url.split_once(['?', '#']).map(|(p, _)| p).unwrap_or(url);
            let last = path.rsplit('/').next().unwrap_or("custom-image.qcow2");
            stem_from_filename(last)
        }
        ImageSource::LocalPath(path) => local_cache_stem(path.file_name()),
    }
}

/// Cache stem for a local image file name, distinct even when it is not UTF-8.
///
/// A file name that is not valid UTF-8 cannot be rendered, and falling back to one
/// shared name (`custom-image`) would map every such image onto the same cache entry:
/// two different images would keep evicting each other and be re-downloaded on every
/// switch. The fallback therefore carries a hash of the raw name bytes, which is stable
/// across runs and different for different files.
fn local_cache_stem(name: Option<&std::ffi::OsStr>) -> String {
    if let Some(text) = name.and_then(|name| name.to_str()) {
        return stem_from_filename(text);
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.map(|name| name.as_encoded_bytes()).unwrap_or_default() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("custom-image-{hash:016x}")
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
    let len_sidecar = PathBuf::from(format!("{}.len", tmp_path.display()));
    let _ = tokio::fs::remove_file(&len_sidecar).await;
    if let Some(total) = total_size {
        // Sidecar so external watchers (orion-scheduler SSE) can show percent.
        let _ = tokio::fs::write(&len_sidecar, total.to_string()).await;
    }

    let mut file = File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create file at {}", tmp_path.display()))?;

    let mut stream = response.bytes_stream();
    let idle = std::time::Duration::from_secs(60);
    let mut downloaded: u64 = 0;
    let mut last_logged: u64 = 0;
    const LOG_EVERY_BYTES: u64 = 32 * 1024 * 1024;

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
        info!("Downloading image: 0 / {} MiB", total / (1024 * 1024));
    } else {
        download_span.pb_set_style(&style_unknown);
        download_span.pb_set_length(u64::MAX);
        info!("Downloading image (size unknown)");
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

        if downloaded.saturating_sub(last_logged) >= LOG_EVERY_BYTES {
            last_logged = downloaded;
            if let Some(total) = total_size {
                let pct = (100.0 * downloaded as f64 / total as f64).min(100.0);
                info!(
                    "Downloading image: {} / {} MiB ({:.0}%)",
                    downloaded / (1024 * 1024),
                    total / (1024 * 1024),
                    pct
                );
            } else {
                info!("Downloading image: {} MiB …", downloaded / (1024 * 1024));
            }
        }
    }

    let hash = hasher.finalize_hex();

    // A proxy or server that closes the stream early ends the loop with a clean EOF, so the
    // byte count is the only evidence of a truncated transfer. Check it before the `.part`
    // file is promoted, otherwise the user is told the *checksum* is wrong when in fact
    // only part of the image arrived.
    if let Some(problem) = truncation_problem(total_size, downloaded) {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        let _ = tokio::fs::remove_file(&len_sidecar).await;
        bail!("{problem} (from {url})");
    }

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
    let _ = tokio::fs::remove_file(&len_sidecar).await;

    info!("Download completed");
    Ok(hash)
}

/// Describe a transfer whose byte count does not match the advertised length.
///
/// `None` when the length was unknown (chunked responses) or matched exactly.
fn truncation_problem(expected: Option<u64>, downloaded: u64) -> Option<String> {
    let expected = expected?;
    if expected == downloaded {
        return None;
    }
    Some(if downloaded < expected {
        format!(
            "download truncated after {downloaded} of {expected} bytes ({} bytes missing); retry the download",
            expected - downloaded
        )
    } else {
        format!(
            "download sent {downloaded} bytes but only {expected} were announced; the response is corrupt"
        )
    })
}

/// Reject a fetched image whose digest does not match, deleting the unusable file.
///
/// Leaving the file behind wastes a full image on disk and keeps a corrupt artifact in the
/// cache directory, where a later run could mistake it for a usable image. The removal can
/// fail on its own - a read-only cache directory, a full disk refusing the unlink - so the
/// error reports what happened to the file and not what was attempted: a caller told "the file
/// was removed" looks everywhere for the corrupt image except where it still is.
async fn verify_fetched(dest: &Path, expected_hash: &str, computed: &str) -> Result<()> {
    if computed.eq_ignore_ascii_case(expected_hash) {
        return Ok(());
    }
    // No file left behind is the fact the caller needs, whether this call removed it or an
    // earlier one did; anything else means the corrupt image is still there.
    let removal_failure = match tokio::fs::remove_file(dest).await {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => Some(error),
    };
    match removal_failure {
        None => bail!(
            "hash mismatch for {}: expected {}, got {}; the file was removed",
            dest.display(),
            expected_hash,
            computed
        ),
        Some(error) => bail!(
            "hash mismatch for {}: expected {}, got {}; the corrupt file is still on disk \
             because removing it failed ({error}); delete it before the next run",
            dest.display(),
            expected_hash,
            computed
        ),
    }
}

/// Whether two paths name the same file on disk.
///
/// Device and inode decide, not the spelling: `./a`, an absolute path, a hard link and a
/// symlink all reach the same file, and only the inode knows. A destination that does not
/// exist yet is a different file by construction.
fn names_the_same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let (Ok(a), Ok(b)) = (std::fs::metadata(a), std::fs::metadata(b)) else {
        return false;
    };
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Refuse a copy whose source is the destination.
///
/// `copy_with_hash` opens the destination for writing (truncating it) before it reads the
/// source. When both name one file — the same path, a hard link, a symlink — that truncation
/// destroys the image it is about to copy: the copy then reads zero bytes, and the digest
/// check rejects and deletes the emptied file. The user loses their image and the error blames
/// a hash mismatch. Refusing before anything is opened is the only outcome that keeps the file.
fn ensure_copy_has_two_files(src: &Path, dest: &Path) -> Result<()> {
    if !names_the_same_file(src, dest) {
        return Ok(());
    }
    bail!(
        "the local image source {} and the cache file {} are the same file: copying would \
         truncate the image before it is read, so nothing was written.\n\
         Point `source` at the image where it lives instead of inside the image cache \
         directory, or move the image there under the name Qlean wants to cache it under.",
        src.display(),
        dest.display()
    )
}

/// Fetch image file from remote source or local path and verify it against the expected hash.
/// Magic bytes every qcow2 image starts with.
const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xfb];

/// Refuse a Windows image that is not qcow2.
///
/// `Machine::new` builds the overlay with `-F qcow2`, so a raw, VHDX or VMDK image fails
/// deep inside `qemu-img create` with `Image is not in qcow2 format` and no hint about what
/// to do — and for a local source only after the whole image was copied into the cache.
/// Four bytes are enough to say so at the door, with the conversion command.
fn ensure_windows_image_is_qcow2(path: &Path, what: &str) -> Result<()> {
    use std::io::Read;

    let mut magic = [0u8; QCOW2_MAGIC.len()];
    let observed = std::fs::File::open(path)
        .with_context(|| format!("failed to open {what} at {}", path.display()))
        .and_then(|mut file| {
            let mut read = 0;
            while read < magic.len() {
                match file.read(&mut magic[read..]) {
                    Ok(0) => break,
                    Ok(n) => read += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to read {what} at {}", path.display())
                        });
                    }
                }
            }
            Ok(magic[..read].to_vec())
        })?;

    anyhow::ensure!(
        observed == QCOW2_MAGIC,
        "the {what} at {} is not a qcow2 image: it starts with {:02x?}, but a qcow2 image \
         starts with {QCOW2_MAGIC:02x?}. Windows guests need qcow2 because Qlean creates a \
         qcow2 overlay on top of the image; convert it once with \
         `qemu-img convert -O qcow2 <input> <output>.qcow2`, then point `source` at that file \
         and `digest` at its sha256",
        path.display(),
        observed
    );
    Ok(())
}

async fn fetch_from_source(
    source: &ImageSource,
    dest: &PathBuf,
    expected_hash: &str,
    hash_type: ShaType,
    guest_os: GuestOs,
) -> Result<()> {
    match source {
        ImageSource::Url(url) => {
            let computed = download_with_hash(url, dest, hash_type.clone()).await?;
            verify_fetched(dest, expected_hash, &computed).await?;
            if guest_os == GuestOs::Windows {
                ensure_windows_image_is_qcow2(dest, "downloaded Windows image")?;
            }
        }
        ImageSource::LocalPath(src) => {
            anyhow::ensure!(src.exists(), "file does not exist: {}", src.display());
            // Before the copy, not after: a wrong format must not cost a multi-gigabyte
            // copy into the cache (and must not fill the disk the guest needs).
            if guest_os == GuestOs::Windows {
                ensure_windows_image_is_qcow2(src, "Windows source image")?;
            }
            ensure_copy_has_two_files(src, dest)?;
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("failed to create dir {}", parent.display()))?;
            }

            // Install through a `.part` file, exactly like the download path: a copy that dies
            // half way must not leave a truncated file at the cache path, where the next run
            // would trust it and `qemu-img` would build an overlay on top of it.
            let part = dest.with_extension("part");
            let _ = tokio::fs::remove_file(&part).await;
            let (src_path, part_path) = (src.clone(), part.clone());
            let copied = tokio::task::spawn_blocking(move || {
                copy_with_hash(&src_path, &part_path, &hash_type)
            })
            .await
            .with_context(|| "copy/hash task failed")?;
            let computed = match copied {
                Ok(computed) => computed,
                Err(error) => {
                    let _ = tokio::fs::remove_file(&part).await;
                    return Err(error);
                }
            };

            tokio::fs::rename(&part, dest).await.with_context(|| {
                format!(
                    "failed to move the copied image {} -> {}",
                    part.display(),
                    dest.display()
                )
            })?;

            verify_fetched(dest, expected_hash, &computed).await?;
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

    /// Guest operating system family of this image.
    pub fn guest_os(&self) -> GuestOs {
        self.guest_os
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

        let name = image_cache_name(
            config.guest_os,
            config.distro,
            config.arch,
            &override_source,
            override_digest.as_ref(),
        )?;

        if let Ok(image) = Self::load(&name).await {
            ensure_cached_guest_os(&name, config.guest_os, image.guest_os)?;
            if let Some((expected_type, expected_hex)) = &override_digest {
                anyhow::ensure!(
                    &image.digest.0 == expected_type
                        && image.digest.1.eq_ignore_ascii_case(expected_hex),
                    "cached image digest mismatch for {}: expected {:?}:{}, got {:?}:{}",
                    name,
                    expected_type,
                    expected_hex,
                    image.digest.0,
                    image.digest.1
                );
            }
            // A cache entry that predates (or bypassed) the format check must not reach
            // `qemu-img`: the overlay it cannot build is the confusing failure this guard
            // exists to prevent.
            if config.guest_os == GuestOs::Windows {
                ensure_windows_image_is_qcow2(image.path(), "cached Windows image")?;
            }
            return Ok(image);
        }

        let dirs = QleanDirs::new()?;
        let image_path = dirs.images.join(format!("{}.qcow2", name));
        let image_digest: (ShaType, String);

        if let (Some(src), Some((digest_type, digest_hex))) = (override_source, override_digest) {
            // If source and digest are provided, fetch from source.
            fetch_from_source(
                &src,
                &image_path,
                &digest_hex,
                digest_type.clone(),
                config.guest_os,
            )
            .await?;

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
                config.guest_os,
            )
            .await?;

            image_digest = (spec.checksum_type, expected_hash);
        }

        let image = Image {
            name: name.to_string(),
            path: image_path,
            arch: config.arch,
            distro: config.distro,
            guest_os: config.guest_os,
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

#[cfg(test)]
impl Image {
    /// Minimal `Image` for unit tests that stop before QEMU is involved.
    pub(crate) fn for_tests(path: std::path::PathBuf) -> Self {
        Self {
            name: "test-image".to_string(),
            path,
            arch: GuestArch::Amd64,
            distro: Distro::Debian,
            guest_os: GuestOs::Linux,
            digest: (ShaType::Sha256, "0".repeat(64)),
            clear: true,
        }
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
    fn test_image_cache_name_prefers_digest() {
        let digest = (ShaType::Sha256, "abc123".to_string());
        let src = Some(ImageSource::Url(
            "https://example.com/orion-images/abc123/debian-13-buck2.qcow2?X-Amz-Signature=deadbeef"
                .to_string(),
        ));
        let name = image_cache_name(
            GuestOs::Linux,
            Distro::Debian,
            GuestArch::Amd64,
            &src,
            Some(&digest),
        )
        .unwrap();
        assert_eq!(name, "sha256-abc123");
    }

    #[test]
    fn test_cache_name_from_url_strips_query() {
        let src = ImageSource::Url(
            "https://example.com/path/debian-13-buck2.qcow2?X-Amz-Signature=deadbeef".to_string(),
        );
        assert_eq!(cache_name_from_source(&src), "debian-13-buck2");
    }

    #[test]
    fn test_two_non_utf8_images_get_distinct_cache_names() {
        use std::os::unix::ffi::OsStrExt;
        let first = ImageSource::LocalPath(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/images/windows-\xff.qcow2",
        )));
        let second = ImageSource::LocalPath(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/images/windows-\xfe.qcow2",
        )));
        let (a, b) = (
            cache_name_from_source(&first),
            cache_name_from_source(&second),
        );
        assert_ne!(
            a, b,
            "two different images must not share one cache entry: {a}"
        );
        assert!(a.starts_with("custom-image-"), "{a}");
        assert_eq!(
            a,
            cache_name_from_source(&first),
            "the fallback name must be stable across runs"
        );
    }

    #[test]
    fn test_utf8_local_image_keeps_its_stem() {
        let src = ImageSource::LocalPath(std::path::PathBuf::from("/images/windows-11.qcow2"));
        assert_eq!(cache_name_from_source(&src), "windows-11");
    }

    #[test]
    fn test_image_config_serde() {
        let config = ImageConfig {
            arch: GuestArch::Amd64,
            distro: Distro::Debian,
            source: Some("https://example.com/image.qcow2".to_string()),
            digest: Some("sha256:abcdef123456".to_string()),
            ..ImageConfig::default()
        };

        let json = serde_json::to_string(&config).unwrap();
        let decoded: ImageConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, config);
    }

    #[test]
    fn test_guest_os_defaults_to_linux() {
        assert_eq!(ImageConfig::default().guest_os, GuestOs::Linux);
        assert_eq!(GuestOs::default(), GuestOs::Linux);

        // Cached image metadata written before `guest_os` existed keeps its meaning.
        let legacy = r#"{
            "name": "debian-13-generic-amd64.qcow2",
            "path": "/tmp/debian.qcow2",
            "arch": "Amd64",
            "distro": "Debian",
            "digest": ["Sha512", "abc"],
            "clear": false
        }"#;
        let decoded: Image = serde_json::from_str(legacy).unwrap();
        assert_eq!(decoded.guest_os, GuestOs::Linux);

        let legacy_config: ImageConfig = serde_json::from_str(
            r#"{
                "arch": "Amd64",
                "distro": "Debian",
                "source": null,
                "digest": null,
                "clear": false
            }"#,
        )
        .unwrap();
        assert_eq!(legacy_config.guest_os, GuestOs::Linux);
    }

    #[test]
    fn test_with_guest_os_builder() {
        let config = ImageConfig::default().with_guest_os(GuestOs::Windows);
        assert_eq!(config.guest_os, GuestOs::Windows);
        // Builder chains keep the remaining fields untouched.
        assert_eq!(config.arch, GuestArch::Amd64);
        assert_eq!(
            ImageConfig::default()
                .with_guest_os(GuestOs::Windows)
                .with_source("https://example.com/win.qcow2".to_string())
                .with_digest("sha256:abc".to_string())
                .guest_os,
            GuestOs::Windows
        );
    }

    #[test]
    fn test_windows_config_requires_source_and_digest() {
        let err = ImageConfig::default()
            .with_guest_os(GuestOs::Windows)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("explicit `source` and `digest`"), "{err}");

        // Only one of the pair is still rejected.
        let err = ImageConfig::default()
            .with_guest_os(GuestOs::Windows)
            .with_source("https://example.com/win.qcow2".to_string())
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("source and digest"), "{err}");

        assert!(
            ImageConfig::default()
                .with_guest_os(GuestOs::Windows)
                .with_source("https://example.com/win.qcow2".to_string())
                .with_digest("sha256:abc".to_string())
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn test_windows_config_rejects_non_amd64() {
        let err = ImageConfig::default()
            .with_guest_os(GuestOs::Windows)
            .with_arch(GuestArch::Aarch64)
            .with_source("https://example.com/win.qcow2".to_string())
            .with_digest("sha256:abc".to_string())
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("only supports amd64"), "{err}");
    }

    #[test]
    fn test_linux_config_keeps_builtin_catalog() {
        // The Linux path may still resolve built-in catalog entries without overrides.
        let name = image_cache_name(
            GuestOs::Linux,
            Distro::Debian,
            GuestArch::Amd64,
            &None,
            None,
        )
        .unwrap();
        assert_eq!(name, "debian-13-generic-amd64");
        assert!(!name.starts_with(WINDOWS_CACHE_PREFIX));
    }

    #[test]
    fn test_windows_cache_name_is_namespaced() {
        let digest = (ShaType::Sha256, "abc123".to_string());
        let src = Some(ImageSource::Url(
            "https://example.com/win.qcow2".to_string(),
        ));
        let windows = image_cache_name(
            GuestOs::Windows,
            Distro::Debian,
            GuestArch::Amd64,
            &src,
            Some(&digest),
        )
        .unwrap();
        let linux = image_cache_name(
            GuestOs::Linux,
            Distro::Debian,
            GuestArch::Amd64,
            &src,
            Some(&digest),
        )
        .unwrap();
        assert_eq!(windows, "windows-sha256-abc123");
        assert_ne!(windows, linux);
    }

    #[test]
    fn test_ensure_cached_guest_os_mismatch() {
        assert!(ensure_cached_guest_os("img", GuestOs::Linux, GuestOs::Linux).is_ok());
        assert!(ensure_cached_guest_os("img", GuestOs::Windows, GuestOs::Windows).is_ok());

        let err = ensure_cached_guest_os("windows-img", GuestOs::Windows, GuestOs::Linux)
            .unwrap_err()
            .to_string();
        assert!(err.contains("belongs to guest OS"), "{err}");
        assert!(ensure_cached_guest_os("linux-img", GuestOs::Linux, GuestOs::Windows).is_err());
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
        let upper = "AB".repeat(64);
        let (algo, hex) = parse_prefixed_digest(&format!("SHA512:{upper}")).unwrap();
        assert_eq!(algo, ShaType::Sha512);
        assert_eq!(hex, upper);

        assert!(parse_prefixed_digest("md5:abcd").is_err());
    }

    #[test]
    fn test_parse_prefixed_digest_rejects_the_wrong_length() {
        // A short digest never matches the computed one, and the mismatch used to be
        // reported as a corrupt image instead of the typo it is.
        let error = parse_prefixed_digest("sha256:abc").unwrap_err().to_string();
        assert!(error.contains("64"), "{error}");
        assert!(error.contains("got 3"), "{error}");

        let error = parse_prefixed_digest(&format!("sha256:{}", "a".repeat(128)))
            .unwrap_err()
            .to_string();
        assert!(error.contains("64"), "{error}");
        assert!(error.contains("got 128"), "{error}");

        let error = parse_prefixed_digest(&format!("sha512:{}", "b".repeat(64)))
            .unwrap_err()
            .to_string();
        assert!(error.contains("128"), "{error}");
        assert!(error.contains("got 64"), "{error}");

        assert!(parse_prefixed_digest(&format!("sha256:{}", "c".repeat(64))).is_ok());
        assert!(parse_prefixed_digest(&format!("sha512:{}", "d".repeat(128))).is_ok());
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

    #[test]
    fn test_truncation_problem_is_silent_for_unknown_or_matching_lengths() {
        assert!(truncation_problem(None, 1234).is_none());
        assert!(truncation_problem(Some(4096), 4096).is_none());
    }

    #[test]
    fn test_truncation_problem_names_short_and_overlong_transfers() {
        let short = truncation_problem(Some(4096), 3000).expect("short transfer must be reported");
        assert!(
            short.contains("truncated after 3000 of 4096 bytes"),
            "{short}"
        );
        assert!(short.contains("1096 bytes missing"), "{short}");

        // A response that delivers more than it announced is corrupt, not truncated.
        let long =
            truncation_problem(Some(4096), 5000).expect("overlong transfer must be reported");
        assert!(long.contains("sent 5000 bytes"), "{long}");
        assert!(long.contains("corrupt"), "{long}");
        assert!(!long.contains("truncated"), "{long}");
    }

    #[tokio::test]
    async fn test_verify_fetched_removes_the_rejected_file() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("image.qcow2");
        tokio::fs::write(&path, b"corrupt").await?;

        let err = verify_fetched(&path, "deadbeef", "feedface")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("hash mismatch"), "{err}");
        assert!(err.contains("removed"), "{err}");
        assert!(
            !path.exists(),
            "a rejected image must not stay in the cache"
        );

        // A matching digest keeps the file.
        tokio::fs::write(&path, b"good").await?;
        verify_fetched(&path, "DEADBEEF", "deadbeef").await?;
        assert!(path.exists(), "case-insensitive match must keep the file");
        Ok(())
    }

    /// The rejection message must describe the file that is on disk, not the attempt.
    ///
    /// Removing the rejected image can fail on its own (a read-only cache directory, a full
    /// disk). The first version printed "the file was removed" no matter what happened, which
    /// sends the caller looking for the corrupt image everywhere except where it still is, in
    /// the cache a later run reads.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_verify_fetched_does_not_claim_a_removal_that_failed() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir()?;
        let locked = tmp.path().join("locked");
        tokio::fs::create_dir(&locked).await?;
        let path = locked.join("image.qcow2");
        tokio::fs::write(&path, b"corrupt").await?;
        tokio::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).await?;

        let err = verify_fetched(&path, "deadbeef", "feedface")
            .await
            .unwrap_err()
            .to_string();

        tokio::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).await?;
        assert!(err.contains("hash mismatch"), "{err}");
        assert!(
            path.exists(),
            "the setup must make the removal fail, otherwise this test proves nothing"
        );
        assert!(
            !err.contains("was removed"),
            "the message claims a removal that did not happen: {err}"
        );
        assert!(err.contains("still on disk"), "{err}");
        assert!(err.contains("image.qcow2"), "{err}");

        // ... and with a removable file the same function does say it removed it, which is
        // the other half of the equation.
        let removable = tmp.path().join("removable.qcow2");
        tokio::fs::write(&removable, b"corrupt").await?;
        let err = verify_fetched(&removable, "deadbeef", "feedface")
            .await
            .unwrap_err()
            .to_string();
        assert!(!removable.exists(), "a removable rejected image is gone");
        assert!(
            err.contains("was removed") && !err.contains("still on disk"),
            "{err}"
        );
        Ok(())
    }

    /// A local image kept inside the cache directory is the destination of its own copy.
    ///
    /// `copy_with_hash` opens the destination for writing before it reads the source, so the
    /// truncation destroys the very image it is about to copy, the verification then rejects
    /// the empty result, and the user's file is gone. Nothing may be written at all here.
    #[tokio::test]
    async fn test_a_local_copy_refuses_to_truncate_its_own_source() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let image = tmp.path().join("win11.qcow2");
        let bytes: &[u8] = b"QFI\xfb a real image";
        tokio::fs::write(&image, bytes).await?;
        let digest = compute_hash(&image, ShaType::Sha256).await?;

        let error = fetch_from_source(
            &ImageSource::LocalPath(image.clone()),
            &image,
            &digest,
            ShaType::Sha256,
            GuestOs::Linux,
        )
        .await
        .expect_err("a copy of a file onto itself must be refused, not performed");
        let message = error.to_string();
        assert!(message.contains("same file"), "{message}");
        assert_eq!(
            tokio::fs::read(&image).await?,
            bytes,
            "the source image must survive the refusal"
        );
        Ok(())
    }

    /// A Windows image that is not qcow2 is refused before it is copied, with a way out.
    ///
    /// The overlay is built with `-F qcow2`, so `qemu-img create` is where this used to
    /// surface: `Image is not in qcow2 format` after the whole image had been copied into
    /// the cache, and without saying what to do about it.
    #[tokio::test]
    async fn test_a_windows_source_that_is_not_qcow2_is_refused_before_it_is_copied() -> Result<()>
    {
        let tmp = tempfile::tempdir()?;
        let src = tmp.path().join("windows-11.vhdx");
        // A VHDX starts with `vhdxfile`; anything that is not the qcow2 magic is refused.
        tokio::fs::write(&src, b"vhdxfile and a lot of bytes").await?;
        let digest = compute_hash(&src, ShaType::Sha256).await?;
        let dest = tmp.path().join("images").join("windows-11.qcow2");

        let error = fetch_from_source(
            &ImageSource::LocalPath(src.clone()),
            &dest,
            &digest,
            ShaType::Sha256,
            GuestOs::Windows,
        )
        .await
        .expect_err("a Windows image that is not qcow2 must be refused");
        let message = error.to_string();
        assert!(message.contains("not a qcow2 image"), "{message}");
        assert!(
            message.contains("qemu-img convert -O qcow2"),
            "the refusal has to name the way out: {message}"
        );
        assert!(
            message.contains(&src.display().to_string()),
            "the refusal has to name the file the user pointed at: {message}"
        );
        assert!(
            !dest.exists() && !dest.with_extension("part").exists(),
            "nothing may be copied for an image that cannot be used"
        );
        assert_eq!(
            tokio::fs::read(&src).await?,
            b"vhdxfile and a lot of bytes",
            "the source must be untouched"
        );
        Ok(())
    }

    /// The check applies to Windows guests only: the Linux path is unchanged.
    #[tokio::test]
    async fn test_a_linux_source_is_copied_without_the_qcow2_check() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let src = tmp.path().join("linux.img");
        let bytes: &[u8] = b"not qcow2, and still the Linux path's business";
        tokio::fs::write(&src, bytes).await?;
        let digest = compute_hash(&src, ShaType::Sha256).await?;
        let dest = tmp.path().join("images").join("linux.img");
        fetch_from_source(
            &ImageSource::LocalPath(src),
            &dest,
            &digest,
            ShaType::Sha256,
            GuestOs::Linux,
        )
        .await?;
        assert_eq!(tokio::fs::read(&dest).await?, bytes);
        Ok(())
    }

    /// A real qcow2 header is not refused: the guard must not cost Windows support.
    #[tokio::test]
    async fn test_a_windows_qcow2_source_is_copied_and_verified() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let src = tmp.path().join("windows-11.qcow2");
        let mut bytes = vec![0x51, 0x46, 0x49, 0xfb];
        bytes.extend_from_slice(&[0u8; 4096]);
        tokio::fs::write(&src, &bytes).await?;
        let digest = compute_hash(&src, ShaType::Sha256).await?;
        let dest = tmp.path().join("images").join("windows-11.qcow2");
        fetch_from_source(
            &ImageSource::LocalPath(src),
            &dest,
            &digest,
            ShaType::Sha256,
            GuestOs::Windows,
        )
        .await?;
        assert_eq!(tokio::fs::read(&dest).await?, bytes);
        Ok(())
    }

    /// The same file reached through a hard link is still one file.
    #[tokio::test]
    async fn test_a_local_copy_from_a_link_to_the_destination_is_refused() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let dest = tmp.path().join("cached.qcow2");
        let bytes: &[u8] = b"linked image bytes";
        tokio::fs::write(&dest, bytes).await?;
        let src = tmp.path().join("source.qcow2");
        std::fs::hard_link(&dest, &src)?;
        let digest = compute_hash(&dest, ShaType::Sha256).await?;

        let error = fetch_from_source(
            &ImageSource::LocalPath(src),
            &dest,
            &digest,
            ShaType::Sha256,
            GuestOs::Linux,
        )
        .await
        .expect_err("a hard link to the destination is the same file");
        assert!(error.to_string().contains("same file"), "{error}");
        assert_eq!(tokio::fs::read(&dest).await?, bytes);
        Ok(())
    }

    /// A local copy is installed the way a download is: through a `.part` file that only
    /// becomes the cache entry once the whole file arrived.
    #[tokio::test]
    async fn test_a_local_copy_is_installed_through_a_part_file() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let src = tmp.path().join("source.qcow2");
        let bytes: &[u8] = b"a local image that is copied into the cache";
        tokio::fs::write(&src, bytes).await?;
        let digest = compute_hash(&src, ShaType::Sha256).await?;

        let cache = tmp.path().join("images");
        let dest = cache.join("source.qcow2");
        // A previous copy that was interrupted leaves this behind; it must not survive.
        tokio::fs::create_dir_all(&cache).await?;
        tokio::fs::write(dest.with_extension("part"), b"half a previous copy").await?;
        fetch_from_source(
            &ImageSource::LocalPath(src.clone()),
            &dest,
            &digest,
            ShaType::Sha256,
            GuestOs::Linux,
        )
        .await?;
        assert_eq!(tokio::fs::read(&dest).await?, bytes);
        assert!(
            !dest.with_extension("part").exists(),
            "a finished copy must not leave its partial file behind"
        );

        // A rejected copy installs nothing and leaves no partial file either, while the
        // source stays intact.
        let rejected = cache.join("rejected.qcow2");
        let error = fetch_from_source(
            &ImageSource::LocalPath(src.clone()),
            &rejected,
            "deadbeef",
            ShaType::Sha256,
            GuestOs::Linux,
        )
        .await
        .expect_err("a wrong digest must be rejected");
        assert!(error.to_string().contains("hash mismatch"), "{error}");
        assert!(!rejected.exists(), "a rejected image must not appear");
        assert!(
            !rejected.with_extension("part").exists(),
            "a rejected copy must not leave a partial file behind"
        );
        assert_eq!(tokio::fs::read(&src).await?, bytes);
        Ok(())
    }
}
