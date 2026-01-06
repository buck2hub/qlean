use std::path::PathBuf;

use anyhow::{Context, Result};
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
            return Err(anyhow::anyhow!(
                "checksum verification failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
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

        let expected_sha512 = checksums_text
            .lines()
            .find(|line| line.contains(name))
            .and_then(|line| line.split_whitespace().next())
            .with_context(|| format!("failed to find {}.qcow2 in SHA512SUMS", name))?
            .to_string();

        let dirs = QleanDirs::new()?;
        let image_path = dirs.images.join(name).join(format!("{}.qcow2", name));

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
            computed_sha512.eq_ignore_ascii_case(&expected_sha512),
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
            return Err(anyhow::anyhow!(
                "guestfish failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
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
            return Err(anyhow::anyhow!(
                "virt-copy-out failed for kernel: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
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
            return Err(anyhow::anyhow!(
                "virt-copy-out failed for initrd: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
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
#[derive(Debug)]
pub enum Image {
    Debian(ImageMeta<Debian>),
    // Add more distros as needed
}

impl Image {
    /// Get the underlying name regardless of distro
    pub fn name(&self) -> &str {
        match self {
            Image::Debian(img) => &img.name,
        }
    }

    /// Get the underlying image path regardless of distro
    pub fn path(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.path,
        }
    }

    /// Get the kernel path regardless of distro
    pub fn kernel(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.kernel,
        }
    }

    /// Get the initrd path regardless of distro
    pub fn initrd(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.initrd,
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
        return Err(anyhow::anyhow!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
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
        return Err(anyhow::anyhow!(
            "sha512sum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha512 = stdout
        .split_whitespace()
        .next()
        .with_context(|| "failed to parse sha512sum output")?
        .to_string();

    Ok(sha512)
}
