use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::debug;

use crate::utils::QleanDirs;

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
    #[serde(skip)]
    pub vendor: A,
    pub checksum: ShaSum,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Distro {
    Debian,
    Ubuntu,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum ShaType {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaSum {
    pub path: PathBuf,
    pub sha_type: ShaType,
}

/// Parses SHA512SUMS format and returns the hash for an exact filename match.
///
/// # Arguments
/// * `checksums_text` - The content of a SHA512SUMS file
/// * `filename` - The exact filename to search for (e.g., "debian-13-generic-amd64.qcow2")
///
/// # Returns
/// The SHA512 hash if found, or None if no exact match exists
pub fn find_sha512_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    checksums_text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let fname = parts.next()?;

        (fname == filename).then(|| hash.to_string())
    })
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

        distro_action.download(name).await?;

        let (kernel, initrd) = distro_action.extract(name).await?;
        let image_path = image_dir.join(format!("{}.qcow2", name));
        let checksum_path = image_dir.join("checksums");
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
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

        let image: ImageMeta<A> = serde_json::from_str(&json_content)
            .with_context(|| format!("failed to parse JSON from {}", json_path.display()))?;

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

    /// Save image metadata to disk
    async fn save(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = serde_json::to_string_pretty(&self)
            .with_context(|| "failed to serialize image config to JSON")?;

        tokio::fs::write(&json_path, json_content)
            .await
            .with_context(|| format!("failed to write image config to {}", json_path.display()))?;

        let (image_hash, kernel_hash, initrd_hash) = match self.checksum.sha_type {
            ShaType::Sha256 => (
                get_sha256(&self.path).await?,
                get_sha256(&self.kernel).await?,
                get_sha256(&self.initrd).await?,
            ),
            ShaType::Sha512 => (
                get_sha512(&self.path).await?,
                get_sha512(&self.kernel).await?,
                get_sha512(&self.initrd).await?,
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
        let response = reqwest::get(&download_url)
            .await
            .with_context(|| format!("failed to download image from {}", download_url))?;

        let mut file = File::create(&image_path)
            .await
            .with_context(|| format!("failed to create image file at {}", image_path.display()))?;

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| "failed to read chunk from stream")?;
            file.write_all(&chunk)
                .await
                .with_context(|| "failed to write image file")?;
        }

        let computed_sha512 = get_sha512(&image_path).await?;
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
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let output = tokio::process::Command::new("guestfish")
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
/// Wrapper enum for different Image types
// ---------------------------------------------------------------------------
// Ubuntu - uses pre-extracted kernel/initrd from official cloud images
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Ubuntu {}

impl ImageAction for Ubuntu {
    async fn download(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Ubuntu noble (24.04 LTS) cloud image base URL
        let base_url = "https://cloud-images.ubuntu.com/noble/current";

        // Download qcow2 image
        let qcow2_url = format!("{}/noble-server-cloudimg-amd64.img", base_url);
        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        download_file(&qcow2_url, &qcow2_path).await?;

        // Download pre-extracted kernel
        let kernel_url = format!(
            "{}/unpacked/noble-server-cloudimg-amd64-vmlinuz-generic",
            base_url
        );
        let kernel_path = image_dir.join("vmlinuz");
        download_file(&kernel_url, &kernel_path).await?;

        // Download pre-extracted initrd
        let initrd_url = format!(
            "{}/unpacked/noble-server-cloudimg-amd64-initrd-generic",
            base_url
        );
        let initrd_path = image_dir.join("initrd.img");
        download_file(&initrd_url, &initrd_path).await?;

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        // Files already downloaded in download() phase
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let kernel = image_dir.join("vmlinuz");
        let initrd = image_dir.join("initrd.img");

        anyhow::ensure!(kernel.exists(), "kernel file not found after download");
        anyhow::ensure!(initrd.exists(), "initrd file not found after download");

        Ok((kernel, initrd))
    }

    fn distro(&self) -> Distro {
        Distro::Ubuntu
    }
}

// Helper function to download a file
async fn download_file(url: &str, dest: &PathBuf) -> Result<()> {
    debug!("Downloading {} to {}", url, dest.display());
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to download from {}", url))?;

    let mut file = File::create(dest)
        .await
        .with_context(|| format!("failed to create file at {}", dest.display()))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| "failed to read chunk from stream")?;
        file.write_all(&chunk)
            .await
            .with_context(|| "failed to write to file")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Image wrapper enum
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Image {
    Debian(ImageMeta<Debian>),
    // Add more distros as needed
    Ubuntu(ImageMeta<Ubuntu>),
}

impl Image {
    /// Get the underlying name regardless of distro
    pub fn name(&self) -> &str {
        match self {
            Image::Debian(img) => &img.name,
            Image::Ubuntu(img) => &img.name,
        }
    }
    /// Get the underlying image path regardless of distro
    pub fn path(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.path,
            Image::Ubuntu(img) => &img.path,
        }
    }
    /// Get the kernel path regardless of distro
    pub fn kernel(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.kernel,
            Image::Ubuntu(img) => &img.kernel,
        }
    }
    /// Get the initrd path regardless of distro
    pub fn initrd(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.initrd,
            Image::Ubuntu(img) => &img.initrd,
        }
    }
}

/// Factory function to create Image instances based on distro
pub async fn create_image(distro: Distro, name: &str) -> Result<Image> {
    match distro {
        Distro::Debian => {
            let image = ImageMeta::<Debian>::create(name).await?;
            Ok(Image::Debian(image))
        } // Add more distros as needed
        Distro::Ubuntu => {
            let image = ImageMeta::<Ubuntu>::create(name).await?;
            Ok(Image::Ubuntu(image))
        }
    }
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
    use super::{Debian, Distro, ImageAction, find_sha512_for_file, get_sha512};
    use crate::utils::QleanDirs;
    use anyhow::Result;
    use serial_test::serial;

    #[test]
    fn test_find_sha512_for_exact_filename() {
        let checksums = "\
748f52b959f63352e1e121508cedeae2e66d3e90be00e6420a0b8b9f14a0f84dc54ed801fb5be327866876268b808543465b1613c8649efeeb5f987ff9df1549  debian-13-generic-amd64.json
\
f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65  debian-13-generic-amd64.qcow2
\
9fd031ef5dda6479c8536a0ab396487113303f4924a2941dc4f9ef1d36376dfb8ae7d1ca5f4dfa65ad155639e9a5e61093c686a8e85b51d106c180bce9ac49bc  debian-13-generic-amd64.raw";
        // Should match exact qcow2 filename, not json with same prefix
        let result = find_sha512_for_file(checksums, "debian-13-generic-amd64.qcow2");
        assert_eq!(
            result,
            Some("f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65".to_string())
        );
        // Should match json file exactly
        let result = find_sha512_for_file(checksums, "debian-13-generic-amd64.json");
        assert_eq!(
            result,
            Some("748f52b959f63352e1e121508cedeae2e66d3e90be00e6420a0b8b9f14a0f84dc54ed801fb5be327866876268b808543465b1613c8649efeeb5f987ff9df1549".to_string())
        );
        // Should not match partial names
        let result = find_sha512_for_file(checksums, "debian-13-generic-amd64");
        assert_eq!(result, None);
    }

    #[test]
    fn test_distro_enum_variants() {
        let variants = vec![Distro::Debian, Distro::Ubuntu];
        assert_eq!(variants.len(), 2);
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn download_real_qcow2_and_validate_checksum() -> Result<()> {
        let name = "debian-13-generic-amd64";
        let target = format!("{name}.qcow2");

        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);
        tokio::fs::create_dir_all(&image_dir).await?;
        let qcow_path = image_dir.join(&target);
        if qcow_path.exists() {
            tokio::fs::remove_file(&qcow_path).await?;
        }

        let debian = Debian::default();
        debian.download(name).await?;

        let checksums_url = "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS";
        let checksums_text = reqwest::get(checksums_url).await?.text().await?;
        let expected = find_sha512_for_file(&checksums_text, &target)
            .expect("missing qcow2 checksum entry in SHA512SUMS");

        let computed = get_sha512(&qcow_path).await?;
        // Clean up downloaded image before assertion to ensure cleanup happens even on failure
        if qcow_path.exists() {
            tokio::fs::remove_file(&qcow_path).await?;
        }

        assert_eq!(computed.to_lowercase(), expected.to_lowercase());

        Ok(())
    }
}
