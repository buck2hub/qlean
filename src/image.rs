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
use tracing::{debug, info, warn};

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

/// Parses checksum text and returns the hash for a filename.
pub fn find_sha512_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    find_hash_for_file(checksums_text, filename)
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

fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

async fn fetch_ubuntu_sha256sums(base_url: &str) -> Result<String> {
    let primary = join_url(base_url, "SHA256SUMS");
    match fetch_text(&primary).await {
        Ok(text) => Ok(text),
        Err(primary_err) => {
            let fallback = join_url(base_url, "SHA256SUMS.txt");
            fetch_text(&fallback).await.with_context(|| {
                format!(
                    "failed to fetch Ubuntu checksums from {} or {} ({:#})",
                    primary, fallback, primary_err
                )
            })
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedUbuntuCloudImage {
    base_url: String,
    disk_name: String,
    disk_sha256: String,
}

fn pick_existing_ubuntu_name(checksums: &str, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|name| {
            checksums.contains(&format!(" {}", name)) || checksums.contains(&format!(" *{}", name))
        })
        .map(|name| (*name).to_string())
}

async fn resolve_ubuntu_noble_cloudimg() -> Result<ResolvedUbuntuCloudImage> {
    let bases = [
        "https://cloud-images.ubuntu.com/releases/noble/release",
        "https://cloud-images.ubuntu.com/noble/current",
        "https://cloud-images.ubuntu.com/daily/server/releases/noble/release",
    ];

    let mut last_err: Option<anyhow::Error> = None;

    for (idx, base) in bases.iter().enumerate() {
        info!("Ubuntu metadata source {}/{}", idx + 1, bases.len());

        let checksums = match fetch_ubuntu_sha256sums(base).await {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let disk_name = match pick_existing_ubuntu_name(
            &checksums,
            &[
                "ubuntu-24.04-server-cloudimg-amd64.img",
                "noble-server-cloudimg-amd64.img",
            ],
        ) {
            Some(v) => v,
            None => {
                last_err = Some(anyhow::anyhow!(
                    "Ubuntu SHA256SUMS did not contain amd64 cloud image entry"
                ));
                continue;
            }
        };

        let disk_sha256 = match ubuntu_sha256_for(&checksums, &disk_name) {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        return Ok(ResolvedUbuntuCloudImage {
            base_url: (*base).to_string(),
            disk_name,
            disk_sha256,
        });
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("failed to resolve Ubuntu cloud image metadata")))
}

fn ubuntu_sha256_for(checksums: &str, filename: &str) -> Result<String> {
    find_hash_for_file(checksums, filename)
        .with_context(|| format!("Ubuntu SHA256SUMS did not contain hash for {}", filename))
}

async fn fetch_text(url: &str) -> Result<String> {
    // Keep metadata fetches snappy: if a mirror is slow/hung, we fall back.
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

// ---------------------------------------------------------------------------
// Fedora/Arch "latest stable" resolvers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ResolvedRemote {
    /// Candidate URLs to try in order. Mirrors can hang; we retry/fallback.
    urls: Vec<String>,
    sha256: String,
}

/// Query endoflife.date for the latest maintained Fedora release number.
///
/// This endpoint is stable and returns structured JSON. We select the first
/// release entry where `isMaintained=true` and `isEol=false`.
const FALLBACK_FEDORA_RELEASE: &str = "43";

async fn resolve_latest_fedora_release() -> Result<String> {
    #[derive(Deserialize)]
    struct EolResp {
        result: EolResult,
    }
    #[derive(Deserialize)]
    struct EolResult {
        releases: Vec<EolRelease>,
    }
    #[derive(Deserialize)]
    struct EolRelease {
        name: String,
        #[serde(default, rename = "isEol")]
        is_eol: bool,
        #[serde(default, rename = "isMaintained")]
        is_maintained: bool,
    }

    // Public JSON API documented on https://endoflife.date/fedora
    let url = "https://endoflife.date/api/v1/products/fedora/";
    match fetch_text(url).await {
        Ok(body) => {
            let parsed: EolResp = serde_json::from_str(&body)
                .with_context(|| "failed to parse Fedora release JSON")?;

            let latest = parsed
                .result
                .releases
                .into_iter()
                .find(|r| r.is_maintained && !r.is_eol)
                .map(|r| r.name)
                .with_context(|| "could not determine latest maintained Fedora release")?;

            Ok(latest)
        }
        Err(err) => {
            warn!(
                "failed to query endoflife.date for latest Fedora release ({}); falling back to {}",
                err, FALLBACK_FEDORA_RELEASE
            );
            Ok(FALLBACK_FEDORA_RELEASE.to_string())
        }
    }
}

/// Resolve the latest Fedora Cloud Base Generic qcow2 URL and its SHA256.
///
/// Implementation strategy:
/// 1) Determine the latest maintained Fedora version.
/// 2) Fetch an HTML directory listing from one of several known mirrors.
/// 3) Parse the directory listing to locate the *exact* qcow2 filename and
///    the corresponding CHECKSUM file name.
/// 4) Download the CHECKSUM file and extract the SHA256 for the qcow2.
async fn resolve_latest_fedora_cloud_qcow2() -> Result<ResolvedRemote> {
    let ver = resolve_latest_fedora_release().await?;

    // Mirror directory patterns differ. We try a small set of mirrors known to
    // provide HTML listings. We keep this list short to reduce fragility.
    // Order matters: prefer official redirector first, then a couple of mirrors
    // that typically provide directory listings.
    let candidates = [
        format!(
            "https://download.fedoraproject.org/pub/fedora/linux/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://ftp2.osuosl.org/pub/fedora/linux/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://mirrors.oit.uci.edu/fedora/linux/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://mirrors.telepoint.bg/fedora/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://mirrors.kernel.org/fedora/releases/{}/Cloud/x86_64/images/",
            ver
        ),
    ];

    // Collect all mirrors where we can fetch a usable listing. We'll parse once
    // and then try downloads across all mirrors.
    let mut good_bases: Vec<String> = Vec::new();
    let mut listing_html: Option<String> = None;
    for u in &candidates {
        match fetch_text(u).await {
            Ok(text) => {
                if text.contains("Fedora-Cloud-Base-Generic") && text.contains("CHECKSUM") {
                    good_bases.push(u.clone());
                    if listing_html.is_none() {
                        listing_html = Some(text);
                    }
                }
            }
            Err(e) => {
                debug!("Fedora listing fetch failed for {}: {:#}", u, e);
            }
        }
    }

    anyhow::ensure!(
        !good_bases.is_empty(),
        "failed to fetch Fedora Cloud images listing from mirrors"
    );
    let listing_html = listing_html.unwrap();

    let (qcow2_name, checksum_name) = parse_fedora_cloud_listing(&listing_html, &ver)?;

    // Build base URLs. Prefer bases where listing worked, but also try the
    // full candidate set as a fallback (a mirror may block directory listing
    // but still serve the file).
    let mut bases = good_bases;
    for c in &candidates {
        if !bases.iter().any(|b| b == c) {
            bases.push(c.clone());
        }
    }

    // Fetch CHECKSUM across mirrors too. Relying on a single mirror defeats
    // the multi-mirror resilience we provide for the qcow2 download.
    let sha256 = fetch_fedora_checksum_sha256(&bases, &checksum_name, &qcow2_name).await?;

    let urls = bases
        .into_iter()
        .map(|base| format!("{}{}", base, qcow2_name))
        .collect::<Vec<_>>();

    Ok(ResolvedRemote { urls, sha256 })
}

async fn fetch_fedora_checksum_sha256(
    bases: &[String],
    checksum_name: &str,
    qcow2_name: &str,
) -> Result<String> {
    let mut last_err: Option<anyhow::Error> = None;

    for base in bases {
        let checksum_url = format!("{}{}", base, checksum_name);
        match fetch_text(&checksum_url).await {
            Ok(text) => {
                if let Some(sha) = find_hash_for_file(&text, qcow2_name) {
                    return Ok(sha);
                }

                last_err = Some(anyhow::anyhow!(
                    "checksum file {} did not contain hash for {}",
                    checksum_url,
                    qcow2_name
                ));
            }
            Err(e) => {
                debug!("Fedora CHECKSUM fetch failed for {}: {:#}", checksum_url, e);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("failed to fetch Fedora CHECKSUM from mirrors")))
}

fn parse_fedora_cloud_listing(listing_html: &str, ver: &str) -> Result<(String, String)> {
    // Parse filename candidates.
    // Listings generally contain only one compose, so the first match is fine.
    let qcow2_prefix = format!("Fedora-Cloud-Base-Generic-{}-", ver);
    let qcow2_suffix = ".x86_64.qcow2";
    let mut qcow2_name: Option<String> = None;
    let mut checksum_name: Option<String> = None;

    for token in listing_html
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
    {
        if qcow2_name.is_none() && token.starts_with(&qcow2_prefix) && token.ends_with(qcow2_suffix)
        {
            qcow2_name = Some(token.to_string());
        }
        if checksum_name.is_none()
            && token.starts_with(&format!("Fedora-Cloud-{}-", ver))
            && token.ends_with("-x86_64-CHECKSUM")
        {
            checksum_name = Some(token.to_string());
        }
        if qcow2_name.is_some() && checksum_name.is_some() {
            break;
        }
    }

    let qcow2_name = qcow2_name
        .with_context(|| "could not locate Fedora Cloud Base Generic qcow2 filename in listing")?;
    let checksum_name = checksum_name
        .with_context(|| "could not locate Fedora Cloud CHECKSUM filename in listing")?;

    Ok((qcow2_name, checksum_name))
}

/// Resolve the latest Arch cloud image URL and SHA256.
///
/// Arch publishes stable "latest" URLs plus a sidecar .SHA256 file.
async fn resolve_latest_arch_cloudimg() -> Result<ResolvedRemote> {
    let bases = [
        "https://mirrors.tuna.tsinghua.edu.cn/archlinux/images/latest",
        "https://mirrors.ustc.edu.cn/archlinux/images/latest",
        "https://mirrors.sjtug.sjtu.edu.cn/archlinux/images/latest",
        "https://fastly.mirror.pkgbuild.com/images/latest",
        "https://geo.mirror.pkgbuild.com/images/latest",
        "https://mirror.citrahost.com/archlinux/images/latest",
        "https://mirrors.teamcloud.am/archlinux/images/latest",
        "https://mirror.umd.edu/archlinux/images/latest",
        "https://ftp.jaist.ac.jp/pub/Linux/ArchLinux/images/latest",
    ];
    let filename = "Arch-Linux-x86_64-cloudimg.qcow2";

    info!("Resolving Arch cloud image metadata");

    let mut last_err: Option<anyhow::Error> = None;
    let mut selected_base: Option<&str> = None;
    let mut sha256: Option<String> = None;

    for (idx, base) in bases.iter().enumerate() {
        info!("Arch metadata mirror {}/{}", idx + 1, bases.len());
        let sha_url = format!("{}/{}.SHA256", base, filename);
        match fetch_text(&sha_url).await {
            Ok(text) => {
                if let Some(hash) = find_hash_for_file(&text, filename) {
                    selected_base = Some(*base);
                    sha256 = Some(hash);
                    break;
                }
                last_err = Some(anyhow::anyhow!("invalid checksum format at {}", sha_url));
            }
            Err(e) => {
                debug!("Arch metadata fetch failed for {}: {:#}", sha_url, e);
                last_err = Some(e);
            }
        }
    }

    let selected_base = selected_base.ok_or_else(|| {
        last_err.unwrap_or_else(|| anyhow::anyhow!("no Arch mirror metadata succeeded"))
    })?;
    let sha256 = sha256.expect("sha256 must exist when metadata resolves");

    let mut urls = vec![format!("{}/{}", selected_base, filename)];
    for base in bases {
        if base != selected_base {
            urls.push(format!("{}/{}", base, filename));
        }
    }

    Ok(ResolvedRemote { urls, sha256 })
}

// ---------------------------------------------------------------------------
// Streaming hash functions - optimized for release mode performance
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

/// Download file and compute hash in single pass to avoid reading file twice
async fn download_with_hash_impl(
    url: &str,
    dest_path: &PathBuf,
    hash_type: ShaType,
    slow_link_cutoff: Option<(std::time::Duration, u64)>,
) -> Result<String> {
    // Keep a temp file to avoid leaving a partially-downloaded blob behind.
    let tmp_path = dest_path.with_extension("part");

    debug!("Downloading {} to {}", url, dest_path.display());

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(20))
        // Do NOT set a short global timeout for large images; we handle stalls
        // with an idle timeout on the stream.
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

    // Ensure destination directory exists.
    if let Some(parent) = tmp_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }

    // Start fresh on each attempt.
    let _ = tokio::fs::remove_file(&tmp_path).await;

    let mut file = File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create file at {}", tmp_path.display()))?;

    let mut stream = response.bytes_stream();
    let idle = std::time::Duration::from_secs(60);
    let mut downloaded: u64 = 0;
    let mut last_report: u64 = 0;
    // Report download progress in reasonably small increments. On slower links or in CI,
    // 64MiB can take long enough that the test runner prints a scary "running over 60 seconds"
    // warning with no other output.
    let report_step: u64 = 8 * 1024 * 1024; // 8 MiB
    let started_at = std::time::Instant::now();
    let mut last_report_at = started_at;

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
                if let Some((slow_link_timeout, min_bytes)) = slow_link_cutoff
                    && started_at.elapsed() >= slow_link_timeout
                    && downloaded < min_bytes
                {
                    anyhow::bail!(
                        "download too slow for {} ({} MiB in {:?}); trying next mirror",
                        url,
                        downloaded / (1024 * 1024),
                        started_at.elapsed()
                    );
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
                if let Some((slow_link_timeout, min_bytes)) = slow_link_cutoff
                    && started_at.elapsed() >= slow_link_timeout
                    && downloaded < min_bytes
                {
                    anyhow::bail!(
                        "download too slow for {} ({} MiB in {:?}); trying next mirror",
                        url,
                        downloaded / (1024 * 1024),
                        started_at.elapsed()
                    );
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

    // Atomically move into place.
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

pub async fn download_with_hash(
    url: &str,
    dest_path: &PathBuf,
    hash_type: ShaType,
) -> Result<String> {
    download_with_hash_impl(url, dest_path, hash_type, None).await
}

/// Try downloading a remote file from multiple candidate URLs.
///
/// Mirrors can hang mid-transfer; we apply an idle timeout and move on.
pub async fn download_with_hash_multi(
    urls: &[String],
    dest_path: &PathBuf,
    hash_type: ShaType,
    expected_hex: Option<&str>,
) -> Result<(String, String)> {
    let mut last_err: Option<anyhow::Error> = None;

    for (idx, url) in urls.iter().enumerate() {
        // If a cached file exists and matches expected, short-circuit.
        if let Some(expected) = expected_hex
            && dest_path.exists()
        {
            // Avoid moving `hash_type` (non-Copy) so it can be reused for mirror retries.
            let computed = match &hash_type {
                ShaType::Sha256 => compute_sha256_streaming(dest_path).await,
                ShaType::Sha512 => compute_sha512_streaming(dest_path).await,
            };

            if let Ok(h) = computed
                && h.eq_ignore_ascii_case(expected)
            {
                debug!("Using cached file at {}", dest_path.display());
                return Ok((h, "(cached)".to_string()));
            }
        }

        info!("Trying mirror {}/{}", idx + 1, urls.len());
        debug!("Download attempt {}/{}: {}", idx + 1, urls.len(), url);
        match download_with_hash_impl(
            url,
            dest_path,
            hash_type.clone(),
            Some((std::time::Duration::from_secs(90), 32 * 1024 * 1024)),
        )
        .await
        {
            Ok(h) => {
                if let Some(expected) = expected_hex
                    && !h.eq_ignore_ascii_case(expected)
                {
                    warn!(
                        "hash mismatch from {}: expected {}, got {}",
                        url, expected, h
                    );
                    last_err = Some(anyhow::anyhow!(
                        "hash mismatch from {}: expected {}, got {}",
                        url,
                        expected,
                        h
                    ));
                    // continue to next mirror
                    continue;
                }
                return Ok((h, url.clone()));
            }
            Err(e) => {
                warn!("download failed for {}: {:#}", url, e);
                last_err = Some(e);
                // next mirror
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all download mirrors failed")))
}

/// Download or copy file from ImageSource with hash verification
async fn download_or_copy_with_hash(
    source: &ImageSource,
    dest: &PathBuf,
    expected_hash: &str,
    hash_type: ShaType,
) -> Result<()> {
    match source {
        ImageSource::Url(url) => {
            // Reuse cached download if it matches, otherwise overwrite.
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

            let computed = download_with_hash(url, dest, hash_type.clone()).await?;
            anyhow::ensure!(
                computed.to_lowercase() == expected_hash.to_lowercase(),
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
                computed.to_lowercase() == expected_hash.to_lowercase(),
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

fn candidate_guestfs_appliance_dirs() -> [&'static str; 6] {
    [
        "/usr/lib/guestfs/appliance",
        "/usr/lib64/guestfs/appliance",
        "/usr/local/lib/guestfs/appliance",
        "/usr/local/lib64/guestfs/appliance",
        "/usr/lib/x86_64-linux-gnu/guestfs/appliance",
        "/usr/lib/aarch64-linux-gnu/guestfs/appliance",
    ]
}

fn is_complete_guestfs_appliance(dir: &Path) -> bool {
    dir.join("kernel").exists()
        && dir.join("initrd").exists()
        && dir.join("root").exists()
        && dir.join("README.fixed").exists()
}

#[derive(Debug, Clone)]
struct SuperminKernelBundle {
    kernel: PathBuf,
    modules_dir: PathBuf,
    kernel_version: String,
}

async fn stage_readable_supermin_kernel(
    cache_root: &Path,
    bundle: &SuperminKernelBundle,
) -> Result<SuperminKernelBundle> {
    let stage_dir = cache_root.join("supermin-host-kernel");
    tokio::fs::create_dir_all(&stage_dir)
        .await
        .with_context(|| format!("failed to create {}", stage_dir.display()))?;

    let file_name = bundle
        .kernel
        .file_name()
        .with_context(|| format!("invalid kernel path: {}", bundle.kernel.display()))?;
    let staged_kernel = stage_dir.join(file_name);

    let _ = tokio::fs::remove_file(&staged_kernel).await;
    tokio::fs::copy(&bundle.kernel, &staged_kernel)
        .await
        .with_context(|| {
            format!(
                "failed to copy host kernel {} into {}",
                bundle.kernel.display(),
                stage_dir.display()
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let perms = std::fs::Permissions::from_mode(0o644);
        tokio::fs::set_permissions(&staged_kernel, perms)
            .await
            .with_context(|| format!("failed to chmod {} to 0644", staged_kernel.display()))?;
    }

    Ok(SuperminKernelBundle {
        kernel: staged_kernel,
        modules_dir: bundle.modules_dir.clone(),
        kernel_version: bundle.kernel_version.clone(),
    })
}

async fn clear_known_paths(root: &Path, names: &[&str]) -> Result<()> {
    for name in names {
        let path = root.join(name);
        if !tokio::fs::try_exists(&path).await? {
            continue;
        }
        let meta = tokio::fs::metadata(&path)
            .await
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if meta.is_dir() {
            tokio::fs::remove_dir_all(&path)
                .await
                .with_context(|| format!("failed to clear {}", path.display()))?;
        } else {
            tokio::fs::remove_file(&path)
                .await
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

fn find_supermin_kernel_bundle(root: &Path) -> Option<SuperminKernelBundle> {
    let boot_dir = root.join("boot");
    let modules_root = root.join("lib/modules");

    let mut kernels = std::fs::read_dir(&boot_dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("vmlinuz"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    kernels.sort();

    let mut modules = std::fs::read_dir(&modules_root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    modules.sort();

    for module_dir in modules.iter().rev() {
        let version = module_dir.file_name()?.to_string_lossy().to_string();
        if let Some(kernel) = kernels.iter().rev().find(|kernel| {
            kernel
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains(&version))
                .unwrap_or(false)
        }) {
            return Some(SuperminKernelBundle {
                kernel: kernel.clone(),
                modules_dir: module_dir.clone(),
                kernel_version: version,
            });
        }
    }

    let kernel = kernels.into_iter().last()?;
    let modules_dir = modules.into_iter().last()?;
    let kernel_version = modules_dir.file_name()?.to_string_lossy().to_string();

    Some(SuperminKernelBundle {
        kernel,
        modules_dir,
        kernel_version,
    })
}

fn is_concrete_linux_image_package(name: &str) -> bool {
    name.strip_prefix("linux-image-unsigned-")
        .or_else(|| name.strip_prefix("linux-image-"))
        .and_then(|rest| rest.chars().next())
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
}

fn parse_apt_depends_for_kernel_package(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(dep) = line.strip_prefix("Depends:") {
            let dep = dep.trim();
            if is_concrete_linux_image_package(dep) {
                return Some(dep.to_string());
            }
        }
    }
    None
}

fn parse_apt_search_for_kernel_package(text: &str) -> Option<String> {
    let mut packages = text
        .lines()
        .filter_map(|line| {
            line.split_once(" - ")
                .map(|(name, _)| name.trim().to_string())
        })
        .filter(|name| is_concrete_linux_image_package(name))
        .collect::<Vec<_>>();
    packages.sort();
    packages.into_iter().last()
}

fn derive_modules_package_name(image_package: &str) -> Option<String> {
    let version = image_package
        .strip_prefix("linux-image-unsigned-")
        .or_else(|| image_package.strip_prefix("linux-image-"))?;
    Some(format!("linux-modules-{}", version))
}

async fn resolve_apt_kernel_package_name() -> Result<String> {
    for meta_pkg in ["linux-image-virtual", "linux-image-generic"] {
        let output = tokio::process::Command::new("apt-cache")
            .arg("depends")
            .arg("--important")
            .arg(meta_pkg)
            .output()
            .await
            .with_context(|| format!("failed to execute `apt-cache depends {meta_pkg}`"))?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(pkg) = parse_apt_depends_for_kernel_package(&stdout) {
                return Ok(pkg);
            }
        }
    }

    for pattern in [
        "^linux-image-[0-9].*-generic$",
        "^linux-image-unsigned-[0-9].*-generic$",
        "^linux-image-[0-9].*-virtual$",
    ] {
        let output = tokio::process::Command::new("apt-cache")
            .arg("search")
            .arg(pattern)
            .output()
            .await
            .with_context(|| format!("failed to execute `apt-cache search {pattern}`"))?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(pkg) = parse_apt_search_for_kernel_package(&stdout) {
                return Ok(pkg);
            }
        }
    }

    bail!("failed to locate an apt-downloadable Linux kernel package for supermin on this host")
}

async fn download_apt_package(package_name: &str, download_dir: &Path) -> Result<PathBuf> {
    clear_known_paths(download_dir, &["kernel-download"])
        .await
        .with_context(|| {
            format!(
                "failed to clear stale package cache in {}",
                download_dir.display()
            )
        })?;

    let package_dir = download_dir.join("kernel-download");
    tokio::fs::create_dir_all(&package_dir)
        .await
        .with_context(|| format!("failed to create {}", package_dir.display()))?;

    let output = tokio::process::Command::new("apt")
        .arg("download")
        .arg(package_name)
        .current_dir(&package_dir)
        .output()
        .await
        .with_context(|| format!("failed to execute `apt download {package_name}`"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let sep = if stdout.trim().is_empty() || stderr.trim().is_empty() {
            ""
        } else {
            "\n"
        };
        bail!("{}{}{}", stdout.trim(), sep, stderr.trim());
    }

    let mut entries = tokio::fs::read_dir(&package_dir)
        .await
        .with_context(|| format!("failed to read {}", package_dir.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("deb") {
            return Ok(path);
        }
    }

    bail!(
        "`apt download {}` did not produce a .deb in {}",
        package_name,
        package_dir.display()
    )
}

/// Supermin needs a kernel+modules pair. Some hosts (notably WSL) ship the
/// libguestfs userspace tools but do not provide a local /boot kernel image.
/// In that case, bootstrap a matching bundle from an apt-downloadable kernel package.
async fn prepare_supermin_kernel_bundle(cache_root: &Path) -> Result<SuperminKernelBundle> {
    let cache_dir = cache_root.join("supermin-kernel-cache");
    let extract_root = cache_dir.join("root");

    if let Some(bundle) = find_supermin_kernel_bundle(&extract_root) {
        return Ok(bundle);
    }

    tokio::fs::create_dir_all(&cache_dir)
        .await
        .with_context(|| format!("failed to create {}", cache_dir.display()))?;

    let package_attempt = async {
        clear_known_paths(&cache_dir, &["root", "kernel-download"])
            .await
            .with_context(|| format!("failed to clear {}", cache_dir.display()))?;

        let package_name = resolve_apt_kernel_package_name().await?;
        info!(
            "Preparing a cached Linux kernel package for libguestfs supermin: {}",
            package_name
        );
        let deb_file = download_apt_package(&package_name, &cache_dir).await?;

        tokio::fs::create_dir_all(&extract_root)
            .await
            .with_context(|| format!("failed to create {}", extract_root.display()))?;

        let output = tokio::process::Command::new("dpkg-deb")
            .arg("-x")
            .arg(&deb_file)
            .arg(&extract_root)
            .output()
            .await
            .with_context(|| format!("failed to extract {} with dpkg-deb", deb_file.display()))?;
        if !output.status.success() {
            bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
        }

        if find_supermin_kernel_bundle(&extract_root).is_none()
            && let Some(modules_pkg) = derive_modules_package_name(&package_name)
        {
            info!(
                "The downloaded image package did not include a full modules tree; fetching {} as well",
                modules_pkg
            );
            let modules_deb = download_apt_package(&modules_pkg, &cache_dir).await?;
            let output = tokio::process::Command::new("dpkg-deb")
                .arg("-x")
                .arg(&modules_deb)
                .arg(&extract_root)
                .output()
                .await
                .with_context(|| format!("failed to extract {} with dpkg-deb", modules_deb.display()))?;
            if !output.status.success() {
                bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
            }
        }

        find_supermin_kernel_bundle(&extract_root).with_context(|| {
            format!(
                "downloaded kernel package {} did not contain a usable kernel/modules pair under {}",
                package_name,
                extract_root.display()
            )
        })
    }
    .await;

    match package_attempt {
        Ok(bundle) => Ok(bundle),
        Err(pkg_err) => {
            if let Some(bundle) = find_supermin_kernel_bundle(Path::new("/")) {
                warn!(
                    "Failed to prepare an apt-downloaded kernel bundle for supermin; falling back to a staged host kernel copy: {pkg_err:#}"
                );
                return stage_readable_supermin_kernel(cache_root, &bundle).await;
            }
            Err(pkg_err)
        }
    }
}

async fn run_make_fixed_appliance(
    appliance_dir: &Path,
    kernel_bundle: Option<&SuperminKernelBundle>,
) -> Result<std::process::Output> {
    clear_known_paths(appliance_dir, &["kernel", "initrd", "root"]).await?;

    let mut cmd = tokio::process::Command::new("libguestfs-make-fixed-appliance");
    cmd.arg(appliance_dir);
    if let Some(bundle) = kernel_bundle {
        cmd.env("SUPERMIN_KERNEL", &bundle.kernel)
            .env("SUPERMIN_MODULES", &bundle.modules_dir)
            .env("SUPERMIN_KERNEL_VERSION", &bundle.kernel_version);
    }

    cmd.output().await.with_context(
        || "failed to execute libguestfs-make-fixed-appliance; install libguestfs-tools",
    )
}

async fn try_build_fixed_guestfs_appliance(appliance_dir: &Path) -> Result<()> {
    let first = run_make_fixed_appliance(appliance_dir, None).await?;
    if first.status.success() {
        anyhow::ensure!(
            is_complete_guestfs_appliance(appliance_dir),
            "libguestfs-make-fixed-appliance completed without producing a usable appliance"
        );
        return Ok(());
    }

    let first_stderr = String::from_utf8_lossy(&first.stderr).trim().to_string();
    let needs_explicit_kernel = first_stderr.contains("supermin exited with error status")
        || first_stderr.contains("--copy-kernel")
        || first_stderr.contains("failed to find a suitable kernel");

    if !needs_explicit_kernel {
        bail!("{}", first_stderr);
    }

    let cache_root = appliance_dir.parent().unwrap_or_else(|| Path::new("."));
    let bundle = prepare_supermin_kernel_bundle(cache_root)
        .await
        .with_context(|| "failed to provision a kernel/modules bundle for supermin")?;

    info!(
        "Retrying libguestfs fixed appliance build with explicit SUPERMIN_KERNEL={} and SUPERMIN_MODULES={}",
        bundle.kernel.display(),
        bundle.modules_dir.display()
    );
    let retry = run_make_fixed_appliance(appliance_dir, Some(&bundle)).await?;
    if !retry.status.success() {
        bail!("{}", String::from_utf8_lossy(&retry.stderr).trim());
    }

    anyhow::ensure!(
        is_complete_guestfs_appliance(appliance_dir),
        "libguestfs-make-fixed-appliance completed without producing a usable appliance"
    );
    Ok(())
}

fn parse_appliance_version_code(version: &str) -> Option<i64> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<i64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<i64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<i64>().ok()?;
    Some(major * 1_000_000 + minor * 1_000 + patch)
}

async fn detect_local_libguestfs_version() -> Option<String> {
    let guestfish = tokio::process::Command::new("guestfish")
        .arg("--version")
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&guestfish.stdout);
    if let Some(version) = stdout.split_whitespace().find(|part| {
        part.chars()
            .next()
            .map(|ch| ch.is_ascii_digit())
            .unwrap_or(false)
    }) {
        return Some(version.trim().to_string());
    }

    let probe = tokio::process::Command::new("libguestfs-test-tool")
        .env("LIBGUESTFS_BACKEND", "direct")
        .output()
        .await
        .ok()?;
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    combined.lines().find_map(|line| {
        line.split_once("version=")
            .map(|(_, v)| v.trim().to_string())
    })
}

fn parse_official_appliance_versions(index_html: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let mut cursor = 0;
    let needle = "appliance-";
    let suffix = ".tar.xz";

    while let Some(start_rel) = index_html[cursor..].find(needle) {
        let start = cursor + start_rel + needle.len();
        if let Some(end_rel) = index_html[start..].find(suffix) {
            let version = &index_html[start..start + end_rel];
            if !version.is_empty()
                && version.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
                && !versions.iter().any(|seen| seen == version)
            {
                versions.push(version.to_string());
            }
            cursor = start + end_rel + suffix.len();
        } else {
            break;
        }
    }

    versions
}

fn ordered_appliance_versions(
    local_version: Option<&str>,
    mut versions: Vec<String>,
) -> Vec<String> {
    let local_code = local_version.and_then(parse_appliance_version_code);

    versions.sort_by(|a, b| {
        let a_code = parse_appliance_version_code(a).unwrap_or_default();
        let b_code = parse_appliance_version_code(b).unwrap_or_default();

        match local_code {
            Some(local) => {
                let a_dist = (a_code - local).abs();
                let b_dist = (b_code - local).abs();
                a_dist.cmp(&b_dist).then_with(|| b_code.cmp(&a_code))
            }
            None => b_code.cmp(&a_code),
        }
    });

    versions
}

async fn extract_downloaded_appliance_archive(
    archive_path: &Path,
    appliance_dir: &Path,
) -> Result<()> {
    let list_output = tokio::process::Command::new("tar")
        .arg("-tJf")
        .arg(archive_path)
        .output()
        .await
        .with_context(|| format!("failed to inspect {}", archive_path.display()))?;
    if !list_output.status.success() {
        bail!("{}", String::from_utf8_lossy(&list_output.stderr).trim());
    }

    let listing = String::from_utf8_lossy(&list_output.stdout);
    let top_level = listing
        .lines()
        .find_map(|line| {
            let trimmed = line.trim_matches('/').trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed.split('/').next().map(|part| part.to_string())
            }
        })
        .with_context(|| format!("{} was empty", archive_path.display()))?;

    let output = tokio::process::Command::new("tar")
        .arg("-xJf")
        .arg(archive_path)
        .arg("-C")
        .arg(appliance_dir)
        .arg("--strip-components=1")
        .arg(&top_level)
        .output()
        .await
        .with_context(|| format!("failed to extract {}", archive_path.display()))?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }

    Ok(())
}

async fn validate_fixed_guestfs_appliance(appliance_dir: &Path) -> Result<()> {
    let output = timeout(
        Duration::from_secs(180),
        tokio::process::Command::new("libguestfs-test-tool")
            .env("LIBGUESTFS_BACKEND", "direct")
            .env("LIBGUESTFS_PATH", appliance_dir)
            .output(),
    )
    .await
    .with_context(|| "libguestfs-test-tool timed out while validating the fixed appliance")?
    .with_context(|| "failed to execute libguestfs-test-tool")?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };
    bail!("{details}");
}

async fn try_download_official_guestfs_appliance_version(
    appliance_dir: &Path,
    version: &str,
) -> Result<()> {
    let archive_name = format!("appliance-{version}.tar.xz");
    let archive_url = format!("https://download.libguestfs.org/binaries/appliance/{archive_name}");

    let cache_root = appliance_dir.parent().unwrap_or_else(|| Path::new("."));
    let download_dir = cache_root.join("guestfs-appliance-downloads");
    tokio::fs::create_dir_all(&download_dir)
        .await
        .with_context(|| format!("failed to create {}", download_dir.display()))?;
    let archive_path = download_dir.join(&archive_name);

    let _actual_sha = download_with_hash(&archive_url, &archive_path, ShaType::Sha512).await?;

    clear_known_paths(appliance_dir, &["kernel", "initrd", "root", "README.fixed"]).await?;
    tokio::fs::create_dir_all(appliance_dir)
        .await
        .with_context(|| format!("failed to create {}", appliance_dir.display()))?;

    extract_downloaded_appliance_archive(&archive_path, appliance_dir).await?;

    anyhow::ensure!(
        is_complete_guestfs_appliance(appliance_dir),
        "downloaded {} did not contain a complete fixed appliance",
        archive_name
    );

    validate_fixed_guestfs_appliance(appliance_dir).await
}

async fn provision_official_guestfs_appliance(appliance_dir: &Path) -> Result<()> {
    let local_version = detect_local_libguestfs_version().await;
    let index_html = fetch_text("https://download.libguestfs.org/binaries/appliance/").await?;
    let available = parse_official_appliance_versions(&index_html);
    anyhow::ensure!(
        !available.is_empty(),
        "the upstream appliance index did not advertise any downloadable fixed appliance"
    );

    let candidates = ordered_appliance_versions(local_version.as_deref(), available);
    let mut last_err = None;

    for version in candidates {
        info!(
            "Trying official libguestfs fixed appliance download: version {}",
            version
        );
        match try_download_official_guestfs_appliance_version(appliance_dir, &version).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                warn!(
                    "Official libguestfs appliance {} did not validate on this host: {err:#}",
                    version
                );
                last_err = Some(err);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("failed to provision an official fixed appliance")))
}

async fn ensure_fixed_guestfs_appliance() -> Result<PathBuf> {
    for dir in candidate_guestfs_appliance_dirs() {
        let path = PathBuf::from(dir);
        if is_complete_guestfs_appliance(&path) {
            return Ok(path);
        }
    }

    let dirs = QleanDirs::new()?;
    let appliance_dir = dirs.base.join("guestfs-appliance");
    if is_complete_guestfs_appliance(&appliance_dir) {
        return Ok(appliance_dir);
    }

    tokio::fs::create_dir_all(&appliance_dir)
        .await
        .with_context(|| format!("failed to create {}", appliance_dir.display()))?;

    if let Err(download_err) = provision_official_guestfs_appliance(&appliance_dir).await {
        warn!(
            "Official libguestfs appliance download failed; falling back to local fixed-appliance build: {download_err:#}"
        );
        match try_build_fixed_guestfs_appliance(&appliance_dir).await {
            Ok(()) => {}
            Err(build_err) => bail!(
                "failed to provision a usable libguestfs appliance: {build_err:#}
Tried the official fixed appliance download first, then a local libguestfs-make-fixed-appliance build."
            ),
        }
    }

    Ok(appliance_dir)
}

async fn run_guestfs_tool(
    program: &str,
    args: &[&OsStr],
    current_dir: &Path,
) -> Result<std::process::Output> {
    async fn run_once(
        program: &str,
        args: &[&OsStr],
        current_dir: &Path,
        appliance: Option<&Path>,
    ) -> Result<std::process::Output> {
        let mut cmd = tokio::process::Command::new(program);
        cmd.env("LIBGUESTFS_BACKEND", "direct")
            .current_dir(current_dir);
        if let Some(appliance_dir) = appliance {
            cmd.env("LIBGUESTFS_PATH", appliance_dir);
        }
        for a in args {
            cmd.arg(a);
        }
        let child = cmd.output();
        let out = timeout(Duration::from_secs(180), child)
            .await
            .with_context(|| format!("{} timed out after 180s (libguestfs)", program))?
            .with_context(|| format!("failed to execute {}", program))?;
        Ok(out)
    }

    let first = run_once(program, args, current_dir, None).await?;
    if !first.status.success() {
        warn!(
            "{} failed (direct backend): {}",
            program,
            String::from_utf8_lossy(&first.stderr)
        );
    }
    if first.status.success() {
        return Ok(first);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    let needs_fixed = stderr.contains("supermin exited with error status")
        || stderr.contains("/usr/bin/supermin");
    if needs_fixed && std::env::var_os("LIBGUESTFS_PATH").is_none() {
        let appliance_dir = ensure_fixed_guestfs_appliance().await?;
        return run_once(program, args, current_dir, Some(&appliance_dir)).await;
    }

    Ok(first)
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
    if !output.status.success() {
        bail!(
            "guestfish failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn virt_copy_out(image_dir: &Path, file_name: &str, src: &str, kind: &str) -> Result<()> {
    let args = [
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new(src),
        OsStr::new("."),
    ];
    let output = run_guestfs_tool("virt-copy-out", &args, image_dir).await?;
    if !output.status.success() {
        bail!(
            "virt-copy-out failed for {}: {}",
            kind,
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
        let checksums_url = "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS";
        let checksums_text = reqwest::get(checksums_url)
            .await
            .with_context(|| format!("failed to download SHA512SUMS from {}", checksums_url))?
            .text()
            .await
            .with_context(|| format!("failed to read SHA512SUMS text from {}", checksums_url))?;

        let target_filename = format!("{}.qcow2", name);
        let expected_sha512 = find_sha512_for_file(&checksums_text, &target_filename)
            .with_context(|| {
                format!(
                    "failed to find SHA512 checksum entry for {} in remote SHA512SUMS file",
                    target_filename
                )
            })?;

        let dirs = QleanDirs::new()?;
        let image_path = dirs.images.join(name).join(&target_filename);

        let download_url = format!(
            "https://cloud.debian.org/images/cloud/trixie/latest/{}.qcow2",
            name
        );

        // Single-pass download + hash computation
        let computed_sha512 =
            download_with_hash(&download_url, &image_path, ShaType::Sha512).await?;

        // Verify the downloaded file matches the expected checksum
        anyhow::ensure!(
            computed_sha512.to_lowercase() == expected_sha512.to_lowercase(),
            "downloaded image checksum mismatch: expected {}, got {}",
            expected_sha512,
            computed_sha512
        );

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        ensure_extraction_prerequisites().await?;

        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let output = tokio::process::Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("--ro")
            .arg("-a")
            .arg(&file_name)
            .arg("-i")
            .arg("ls")
            .arg("/boot")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| "failed to execute guestfish")?;

        if !output.status.success() {
            bail!(
                "guestfish failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let boot_files = String::from_utf8_lossy(&output.stdout);
        let mut kernel_name = None;
        let mut initrd_name = None;

        for line in boot_files.lines() {
            let file = line.trim();
            if file.starts_with("vmlinuz") {
                kernel_name = Some(file.to_string());
            } else if file.starts_with("initrd.img") {
                initrd_name = Some(file.to_string());
            }
        }

        let kernel_name =
            kernel_name.with_context(|| "failed to find kernel file (vmlinuz*) in /boot")?;
        let initrd_name =
            initrd_name.with_context(|| "failed to find initrd file (initrd.img*) in /boot")?;

        let kernel_src = format!("/boot/{}", kernel_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&kernel_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", kernel_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for kernel: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let initrd_src = format!("/boot/{}", initrd_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&initrd_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", initrd_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for initrd: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let kernel_path = image_dir.join(&kernel_name);
        let initrd_path = image_dir.join(&initrd_name);

        Ok((kernel_path, initrd_path))
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
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let resolved = resolve_ubuntu_noble_cloudimg().await?;
        debug!(
            "Resolved Ubuntu cloud image from {}: disk={}",
            resolved.base_url, resolved.disk_name
        );

        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        let qcow2_url = join_url(&resolved.base_url, &resolved.disk_name);
        download_or_copy_with_hash(
            &ImageSource::Url(qcow2_url),
            &qcow2_path,
            &resolved.disk_sha256,
            ShaType::Sha256,
        )
        .await?;

        Ok(())
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
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let resolved = resolve_latest_fedora_cloud_qcow2().await?;
        debug!(
            "Resolved Fedora Cloud qcow2 (sha256={}): {} mirror(s)",
            resolved.sha256,
            resolved.urls.len()
        );

        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        let (_hash, used_url) = download_with_hash_multi(
            &resolved.urls,
            &qcow2_path,
            ShaType::Sha256,
            Some(&resolved.sha256),
        )
        .await
        .with_context(|| "failed to download Fedora cloud image from all mirrors")?;
        debug!(
            "Fedora cloud image downloaded successfully from {}",
            used_url
        );

        Ok(())
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
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let resolved = resolve_latest_arch_cloudimg().await?;
        debug!(
            "Resolved Arch cloudimg (sha256={}): {} mirror(s)",
            resolved.sha256,
            resolved.urls.len()
        );

        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        let (_hash, used_url) = download_with_hash_multi(
            &resolved.urls,
            &qcow2_path,
            ShaType::Sha256,
            Some(&resolved.sha256),
        )
        .await
        .with_context(|| "failed to download Arch cloud image from all mirrors")?;
        debug!("Arch cloud image downloaded successfully from {}", used_url);

        Ok(())
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
        download_or_copy_with_hash(
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
            download_or_copy_with_hash(
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
            download_or_copy_with_hash(
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
    fn test_find_sha512_for_exact_filename() {
        let checksums = "\
748f52b959f63352e1e121508cedeae2e66d3e90be00e6420a0b8b9f14a0f84dc54ed801fb5be327866876268b808543465b1613c8649efeeb5f987ff9df1549  debian-13-generic-amd64.json
\
f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65  debian-13-generic-amd64.qcow2";
        let result = find_sha512_for_file(checksums, "debian-13-generic-amd64.qcow2");
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

    #[test]
    fn test_parse_apt_depends_for_kernel_package_prefers_concrete_image() {
        let text = r#"
Depends: linux-image-virtual
Depends: linux-image-6.8.0-71-generic
Depends: initramfs-tools
"#;
        assert_eq!(
            parse_apt_depends_for_kernel_package(text).as_deref(),
            Some("linux-image-6.8.0-71-generic")
        );
    }

    #[test]
    fn test_derive_modules_package_name_for_signed_and_unsigned_images() {
        assert_eq!(
            derive_modules_package_name("linux-image-6.8.0-71-generic").as_deref(),
            Some("linux-modules-6.8.0-71-generic")
        );
        assert_eq!(
            derive_modules_package_name("linux-image-unsigned-6.8.0-71-generic").as_deref(),
            Some("linux-modules-6.8.0-71-generic")
        );
    }

    #[test]
    fn test_parse_apt_search_for_kernel_package_picks_latest_match() {
        let text = r#"
linux-image-6.8.0-65-generic - Signed kernel image generic
linux-image-6.8.0-71-generic - Signed kernel image generic
linux-image-generic - Complete Generic Linux kernel and headers
"#;
        assert_eq!(
            parse_apt_search_for_kernel_package(text).as_deref(),
            Some("linux-image-6.8.0-71-generic")
        );
    }

    #[test]
    fn test_parse_fedora_cloud_listing() {
        let html = r#"
            <a href=\"Fedora-Cloud-43-1.6-x86_64-CHECKSUM\">Fedora-Cloud-43-1.6-x86_64-CHECKSUM</a>
            <a href=\"Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2\">Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2</a>
        "#;
        let (qcow2, checksum) = parse_fedora_cloud_listing(html, "43").unwrap();
        assert_eq!(qcow2, "Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2");
        assert_eq!(checksum, "Fedora-Cloud-43-1.6-x86_64-CHECKSUM");
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
