use std::{
    fs::Permissions,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::Output,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, bail};
use nanoid::nanoid;
use russh_sftp::client::fs::{Metadata, ReadDir};
use serde::{Deserialize, Serialize};
use shell_escape::unix::escape;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use walkdir::WalkDir;

use crate::{
    image::Image,
    qemu::launch_qemu,
    ssh::{PersistedSshKeypair, Session, connect_ssh, get_ssh_key},
    utils::{CommandExt, HEX_ALPHABET, QleanDirs, get_free_cid},
};

pub struct Machine {
    id: String,
    image: MachineImage,
    config: MachineConfig,
    keypair: PersistedSshKeypair,
    /// SSH session
    ssh: Option<Session>,
    cid: u32,
    /// QEMU process ID
    pid: Option<u32>,
    /// Indicates whether QEMU is expected to exit.
    /// Used to differentiate between expected shutdowns and crashes.
    qemu_should_exit: Arc<AtomicBool>,
    /// Cancellation token for SSH operations.
    /// This is used to cancel ongoing SSH operations when qemu exits.
    /// Set when the machine is initialized or spawned, cleared on shutdown.
    ssh_cancel_token: Option<CancellationToken>,
}

#[derive(Clone)]
pub struct MachineImage {
    pub overlay: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub seed: PathBuf,
}

#[derive(Clone, Debug)]
pub struct MachineConfig {
    /// Number of CPU cores
    pub core: u32,
    /// Memory in MB
    pub mem: u32,
    /// Disk size in GB (optional)
    pub disk: Option<u32>,
    /// Clear after use
    pub clear: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetaData {
    #[serde(rename = "instance-id")]
    pub instance_id: String,
    #[serde(rename = "local-hostname")]
    pub local_hostname: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserData {
    pub disable_root: bool,
    pub ssh_authorized_keys: Vec<String>,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            core: 2,
            mem: 4096,
            disk: None,
            clear: true,
        }
    }
}

// Core methods for Machine
impl Machine {
    /// Create a new Machine instance
    pub async fn new(image: &Image, config: &MachineConfig) -> Result<Self> {
        // Prepare run directory
        let dirs = QleanDirs::new()?;
        let machine_id = nanoid!(12, &HEX_ALPHABET);
        let run_dir = Path::new(&dirs.runs).join(&machine_id);
        let seed_dir = run_dir.join("seed");
        tokio::fs::create_dir_all(&run_dir).await?;
        tokio::fs::create_dir_all(&seed_dir).await?;

        // Create overlay image
        let mut qemu_img_command = tokio::process::Command::new("qemu-img");
        qemu_img_command
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg("-b")
            .arg(image.path())
            .arg("-F")
            .arg("qcow2")
            .arg(run_dir.join("overlay.img"));
        debug!(
            "Creating overlay image with command:\n{:?}",
            qemu_img_command.to_string()
        );
        let output = qemu_img_command.output().await?;
        if !output.status.success() {
            bail!(
                "Failed to create overlay image: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let overlay_image = run_dir.join("overlay.img");

        // Generate SSH keypair
        let ssh_keypair = get_ssh_key(&dirs.secrets)?;

        // Get a free CID
        let cid = get_free_cid(&dirs.runs, &run_dir)?;

        // Prepare cloud-init config
        let meta_data = MetaData {
            instance_id: format!("VM-{}", &machine_id),
            local_hostname: "qlean-vm".to_string(),
        };
        let mut meta_data_str = serde_yml::to_string(&meta_data)?;
        meta_data_str.insert_str(0, "#cloud-config\n");
        debug!("Writing cloud-init meta-data:\n{}", meta_data_str);
        tokio::fs::write(seed_dir.join("meta-data"), meta_data_str).await?;
        let user_data = UserData {
            disable_root: false,
            ssh_authorized_keys: vec![ssh_keypair.pubkey_str.clone()],
        };
        let mut user_data_str = serde_yml::to_string(&user_data)?;
        user_data_str.insert_str(0, "#cloud-config\n");
        debug!("Writing cloud-init user-data:\n{}", user_data_str);
        tokio::fs::write(seed_dir.join("user-data"), user_data_str).await?;

        // Prepare seed ISO
        let seed_iso_path = run_dir.join("seed.iso");
        let mut xorriso_command = tokio::process::Command::new("xorriso");
        xorriso_command
            .args(["-as", "mkisofs"])
            .args(["-V", "cidata"])
            .args(["-J", "-R"])
            .args(["-o", seed_iso_path.to_str().unwrap()])
            .arg(seed_dir);
        debug!(
            "Creating seed ISO with command:\n{:?}",
            xorriso_command.to_string()
        );
        let output = xorriso_command.output().await?;
        if !output.status.success() {
            bail!(
                "Failed to create seed ISO: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let machine_image = MachineImage {
            overlay: overlay_image.clone(),
            kernel: image.kernel().to_owned(),
            initrd: image.initrd().to_owned(),
            seed: seed_iso_path,
        };

        Ok(Self {
            id: machine_id,
            image: machine_image,
            config: config.clone(),
            keypair: ssh_keypair,
            ssh: None,
            cid,
            pid: None,
            qemu_should_exit: Arc::new(AtomicBool::new(false)),
            ssh_cancel_token: None,
        })
    }

    /// Initialize the machine (first boot)
    pub async fn init(&mut self) -> Result<()> {
        info!("🚀 Initializing VM-{}", self.id);

        // Resize image if needed
        if let Some(resize_gb) = self.config.disk {
            let mut qemu_img_command = tokio::process::Command::new("qemu-img");
            qemu_img_command
                .arg("resize")
                .arg(&self.image.overlay)
                .arg(format!("{}G", resize_gb));
            debug!(
                "Resizing overlay image with command:\n{:?}",
                qemu_img_command.to_string()
            );
            let output = qemu_img_command.output().await?;
            if !output.status.success() {
                bail!(
                    "Failed to resize image: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        if self.ssh_cancel_token.is_none() {
            self.ssh_cancel_token = Some(CancellationToken::new());
        } else {
            bail!("Machine already initialized");
        }

        self.launch(true).await?;

        Ok(())
    }

    /// Spawn the machine (normal boot)
    pub async fn spawn(&mut self) -> Result<()> {
        info!("Spawning VM-{}", self.id);

        if self.ssh_cancel_token.is_none() {
            self.ssh_cancel_token = Some(CancellationToken::new());
        } else {
            bail!("Machine already spawned");
        }

        self.launch(false).await?;

        Ok(())
    }

    /// Execute a command on the machine and return the output
    pub async fn exec<S: AsRef<str>>(&mut self, cmd: S) -> Result<Output> {
        let cmd_ref = cmd.as_ref();
        info!("🧬 Executing command `{}` on VM-{}", cmd_ref, self.id);
        if let Some(ssh) = self.ssh.as_mut() {
            let cancel_token = self
                .ssh_cancel_token
                .as_ref()
                .expect("Machine not initialized or spawned")
                .clone();

            let (exit_code, stdout, stderr) = ssh.call_with_output(cmd_ref, cancel_token).await?;

            Ok(Output {
                status: std::process::ExitStatus::from_raw(exit_code as i32),
                stdout,
                stderr,
            })
        } else {
            Err(anyhow::anyhow!("SSH session not established"))
        }
    }

    /// Shutdown the machine
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(ssh) = self.ssh.as_mut() {
            // Then shut the system down.
            ssh.call(
                "systemctl poweroff",
                self.ssh_cancel_token
                    .as_ref()
                    .expect("Machine not initialized or spawned")
                    .clone(),
            )
            .await?;
            info!("🔌 Shutting down VM-{}", self.id);

            // Tell the QEMU handler it's now fine to wait for exit.
            self.qemu_should_exit.store(true, Ordering::SeqCst);

            // Ignore whatever error we might get from this as we want to close the connection at this
            // point anyway.
            let _ = ssh.close().await;

            // Wait for QEMU process to actually exit
            if let Some(pid) = self.pid {
                debug!("Waiting for QEMU process {} to exit", pid);
                let max_wait_time = Duration::from_secs(30);
                let poll_interval = Duration::from_millis(100);
                let start = std::time::Instant::now();

                loop {
                    // Check if process is still running
                    let process_exists = std::path::Path::new(&format!("/proc/{}", pid)).exists();

                    if !process_exists {
                        debug!("QEMU process {} has exited", pid);
                        break;
                    }

                    if start.elapsed() > max_wait_time {
                        info!(
                            "QEMU process {} did not exit within timeout, force killing",
                            pid
                        );
                        let _ = std::process::Command::new("kill")
                            .arg("-9")
                            .arg(pid.to_string())
                            .output();
                        break;
                    }

                    tokio::time::sleep(poll_interval).await;
                }
            }

            // Clean up runtime files
            let dirs = QleanDirs::new()?;
            let pid_file_path = dirs.runs.join(&self.id).join("qemu.pid");
            let _ = tokio::fs::remove_file(pid_file_path).await;
            self.ssh = None;
            self.pid = None;
            self.ssh_cancel_token = None;

            Ok(())
        } else {
            Err(anyhow::anyhow!("SSH session not established"))
        }
    }

    /// Upload file or directory to the machine
    pub async fn upload<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        local_path: P,
        remote_path: Q,
    ) -> Result<()> {
        let local_path = local_path.as_ref();
        let remote_path = remote_path.as_ref();
        info!(
            "📤 Uploading {:?} to {:?} on VM-{}",
            local_path, remote_path, self.id
        );
        let (ssh, cancel_token) = self.get_ssh()?;

        // Normalize local path type
        let meta = tokio::fs::metadata(local_path).await?;
        if meta.is_file() {
            // Decide final remote target path (dir vs file path)
            let remote_target = {
                let is_dir = {
                    let sftp = ssh.get_sftp().await?;
                    (sftp.read_dir(remote_path.to_string_lossy()).await).is_ok()
                };
                if is_dir {
                    remote_path.join(local_path.file_name().expect("local_path has no basename"))
                } else {
                    remote_path.to_path_buf()
                }
            };

            // Ensure remote parent directory exists
            if let Some(parent) = remote_target.parent() {
                ssh.create_dir_all(parent).await?;
            }

            // Upload single file
            ssh.upload_file(local_path, &remote_target, cancel_token.clone())
                .await?;
        } else if meta.is_dir() {
            // For directory: mirror into remote_path/<basename>
            let base = local_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("local_path has no basename"))?;
            let remote_root = remote_path.join(base);
            ssh.create_dir_all(&remote_root).await?;

            for entry in WalkDir::new(local_path).follow_links(false) {
                let entry = entry?;
                let ty = entry.file_type();

                // Cancellation check
                if cancel_token.is_cancelled() {
                    bail!("Upload cancelled");
                }

                // Relative path under local_path
                let rel = entry
                    .path()
                    .strip_prefix(local_path)
                    .expect("Failed to get relative path");
                let remote_entry = remote_root.join(rel);

                if ty.is_dir() {
                    ssh.create_dir_all(&remote_entry).await?;
                } else if ty.is_file() {
                    if let Some(parent) = remote_entry.parent() {
                        ssh.create_dir_all(parent).await?;
                    }
                    ssh.upload_file(entry.path(), &remote_entry, cancel_token.clone())
                        .await?;
                } else if ty.is_symlink() {
                    // Try to reproduce symlink if possible
                    match tokio::fs::read_link(entry.path()).await {
                        Ok(target) => {
                            // Ensure parent exists
                            if let Some(parent) = remote_entry.parent() {
                                ssh.create_dir_all(parent).await?;
                            }
                            {
                                let sftp = ssh.get_sftp().await?;
                                let _ = sftp
                                    .symlink(
                                        remote_entry.to_string_lossy(),
                                        target.to_string_lossy(),
                                    )
                                    .await; // best-effort
                            }
                        }
                        Err(_) => {
                            // Fallback: ignore or copy as file (we ignore silently)
                        }
                    }
                }
            }
        } else {
            bail!("Unsupported local path type");
        }

        Ok(())
    }

    /// Download file or directory from the machine
    pub async fn download<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        remote_path: P,
        local_path: Q,
    ) -> Result<()> {
        let remote_path = remote_path.as_ref();
        let local_path = local_path.as_ref();
        info!(
            "📥 Downloading {:?} from VM-{} to {:?}",
            remote_path, self.id, local_path
        );
        let (ssh, cancel_token) = self.get_ssh()?;

        // Check remote path type
        let remote_meta = {
            let sftp = ssh.get_sftp().await?;
            sftp.metadata(remote_path.to_string_lossy())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to stat remote path: {}", e))?
        };

        if !remote_meta.is_dir() {
            // Decide final local target path (dir vs file path)
            let local_target = match tokio::fs::metadata(local_path).await {
                Ok(attr) if attr.is_dir() => local_path.join(
                    remote_path
                        .file_name()
                        .ok_or_else(|| anyhow::anyhow!("remote_path has no basename"))?,
                ),
                _ => local_path.to_path_buf(),
            };

            // Ensure local parent directory exists
            if let Some(parent) = local_target.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    anyhow::anyhow!("Failed to create local directory {:?}: {}", parent, e)
                })?;
            }

            // Download single file
            ssh.download_file(remote_path, &local_target, cancel_token.clone())
                .await?;
        } else if remote_meta.is_dir() {
            // For directory: mirror into local_path/<basename>
            let base = remote_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("remote_path has no basename"))?;
            let local_root = local_path.join(base);
            tokio::fs::create_dir_all(&local_root).await.map_err(|e| {
                anyhow::anyhow!("Failed to create local directory {:?}: {}", local_root, e)
            })?;

            // Use walk_remote_dir for DFS traversal
            let entries = ssh
                .walk_remote_dir(
                    remote_path,
                    /*follow_links=*/ false,
                    cancel_token.clone(),
                )
                .await?;

            for e in entries {
                if cancel_token.is_cancelled() {
                    return Err(anyhow::anyhow!("Download cancelled"));
                }

                // Compute local path relative to remote root
                let rel = match e.path().strip_prefix(remote_path) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let local_entry = local_root.join(rel);

                if e.file_type().is_dir() {
                    tokio::fs::create_dir_all(&local_entry).await.map_err(|e| {
                        anyhow::anyhow!("Failed to create local directory {:?}: {}", local_entry, e)
                    })?;
                } else if e.file_type().is_file() {
                    if let Some(parent) = local_entry.parent() {
                        tokio::fs::create_dir_all(parent).await.map_err(|e| {
                            anyhow::anyhow!("Failed to create local directory {:?}: {}", parent, e)
                        })?;
                    }
                    ssh.download_file(e.path(), &local_entry, cancel_token.clone())
                        .await?;
                } else if e.file_type().is_symlink() {
                    // Best-effort: current SFTP attrs may not distinguish symlinks.
                    // Treat as file or skip depending on future capabilities.
                }
            }
        } else {
            bail!("Unsupported remote path type");
        }

        Ok(())
    }

    /// Helper to get SSH session and cancellation token
    fn get_ssh(&mut self) -> Result<(&mut Session, CancellationToken)> {
        let ssh = self
            .ssh
            .as_mut()
            .expect("Machine not initialized or spawned");
        let cancel_token = self
            .ssh_cancel_token
            .as_ref()
            .cloned()
            .expect("Machine not initialized or spawned");
        Ok((ssh, cancel_token))
    }

    /// Launch QEMU and connect SSH concurrently
    async fn launch(&mut self, is_init: bool) -> Result<()> {
        debug!(
            "SSH command for manual debugging:\nssh root@vsock/{} -i {:?}",
            self.cid, self.keypair.privkey_path,
        );

        let qemu_handle = tokio::spawn(launch_qemu(
            self.qemu_should_exit.clone(),
            self.cid,
            self.image.to_owned(),
            self.config.to_owned(),
            self.id.to_owned(),
            is_init,
            self.ssh_cancel_token
                .as_ref()
                .expect("Machine not initialized or spawned")
                .clone(),
        ));
        let ssh_handle = tokio::spawn(connect_ssh(
            self.cid,
            Duration::from_secs(20),
            self.keypair.to_owned(),
            self.ssh_cancel_token
                .as_ref()
                .expect("Machine not initialized or spawned")
                .clone(),
        ));

        // Wait for SSH to complete, or abort SSH if QEMU errors
        tokio::select! {
            result = ssh_handle => {
                // SSH completed, QEMU continues running
                match result {
                    Ok(Ok(session)) => {
                        self.ssh = Some(session);
                        let dirs = QleanDirs::new()?;
                        let runs_dir = dirs.runs;
                        let pid_file_path = runs_dir.join(&self.id).join("qemu.pid");
                        let pid_str = tokio::fs::read_to_string(pid_file_path).await?;
                        self.pid = Some(pid_str.trim().parse()?);
                    }
                    Ok(Err(e)) => bail!(e),
                    Err(e) => bail!("SSH task panicked: {}", e),
                }
            }
            result = qemu_handle => {
                // QEMU completed or errored, cancel SSH task
                self.ssh_cancel_token.as_ref().expect("Machine not initialized or spawned").cancel();
                match result {
                    Ok(Err(e)) => bail!(e),
                    Ok(Ok(())) => bail!("QEMU exited unexpectedly"),
                    Err(e) => bail!("QEMU task error: {}", e),
                }
            }
        }

        Ok(())
    }
}

// Filesystem methods for Machine
impl Machine {
    /// Copies the contents of one file to another.
    /// This function will also copy the permission bits of the original file to the destination file.
    pub async fn copy<P: AsRef<Path>, Q: AsRef<Path>>(&mut self, from: P, to: Q) -> Result<()> {
        let from = from.as_ref();
        let to = to.as_ref();
        let (ssh, cancel_token) = self.get_ssh()?;

        // Validate source and destination semantics to mirror std::fs::copy
        {
            let sftp = ssh.get_sftp().await?;
            let src_meta = sftp
                .metadata(from.to_string_lossy())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to stat source: {e}"))?;
            if src_meta.is_dir() {
                bail!("Source is a directory: {:?}", from);
            }

            if let Ok(dst_meta) = sftp.metadata(to.to_string_lossy()).await
                && dst_meta.is_dir()
            {
                bail!("Destination is a directory: {:?}", to);
            }
        }

        // Use cp inside the guest to avoid round-tripping data over SFTP.
        let cmd = format!(
            "cp -p -- {} {}",
            escape(from.to_string_lossy()),
            escape(to.to_string_lossy())
        );
        let (code, _stdout, stderr) = ssh.call_with_output(&cmd, cancel_token).await?;
        if code != 0 {
            bail!(
                "Failed to copy file (exit code {}): {}",
                code,
                String::from_utf8_lossy(&stderr)
            );
        }

        Ok(())
    }

    /// Creates a new, empty directory at the provided path
    pub async fn create_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        sftp.create_dir(path.to_string_lossy()).await?;

        Ok(())
    }

    /// Recursively create a directory and all of its parent components if they are missing.
    pub async fn create_dir_all<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        ssh.create_dir_all(path).await?;

        Ok(())
    }

    /// Returns `Ok(true)` if the path points at an existing entity.
    pub async fn exists<P: AsRef<Path>>(&mut self, path: P) -> Result<bool> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.try_exists(path.to_string_lossy()).await?)
    }

    /// Creates a new hard link on the filesystem.
    pub async fn hard_link<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        original: P,
        link: Q,
    ) -> Result<()> {
        let original = original.as_ref();
        let link = link.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        sftp.hardlink(original.to_string_lossy(), link.to_string_lossy())
            .await?;

        Ok(())
    }

    /// Given a path, queries the file system to get information about a file, directory, etc.
    pub async fn metadata<P: AsRef<Path>>(&mut self, path: P) -> Result<Metadata> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.metadata(path.to_string_lossy()).await?)
    }

    /// Reads the entire contents of a file into a bytes vector.
    pub async fn read<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.read(path.to_string_lossy()).await?)
    }

    /// Returns an iterator over the entries within a directory.
    pub async fn read_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<ReadDir> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.read_dir(path.to_string_lossy()).await?)
    }

    /// Reads a symbolic link, returning the file that the link points to.
    pub async fn read_link<P: AsRef<Path>>(&mut self, path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        Ok(PathBuf::from(sftp.read_link(path.to_string_lossy()).await?))
    }

    /// Reads the entire contents of a file into a string.
    pub async fn read_to_string<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        let bytes = sftp.read(path.to_string_lossy()).await?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Removes a directory at provided path, after removing all its contents.
    pub async fn remove_dir_all<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        sftp.remove_dir(path.to_string_lossy()).await?;

        Ok(())
    }

    /// Removes a file from the filesystem on VM.
    pub async fn remove_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        sftp.remove_file(path.to_string_lossy()).await?;

        Ok(())
    }

    /// Renames a file or directory to a new name
    pub async fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&mut self, from: P, to: Q) -> Result<()> {
        let from = from.as_ref();
        let to = to.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        sftp.rename(from.to_string_lossy(), to.to_string_lossy())
            .await?;

        Ok(())
    }

    /// Changes the permissions found on a file or a directory.
    pub async fn set_permissions<P: AsRef<Path>>(
        &mut self,
        path: P,
        perm: Permissions,
    ) -> Result<()> {
        let path = path.as_ref();
        let (ssh, _) = self.get_ssh()?;

        {
            let sftp = ssh.get_sftp().await?;
            let mut meta = sftp
                .metadata(path.to_string_lossy())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to stat file: {}", e))?;

            let mode = perm.mode();
            meta.permissions = Some(mode);

            sftp.set_metadata(path.to_string_lossy(), meta).await?;
        }

        Ok(())
    }

    /// Writes a slice as the entire contents of a file.
    ///
    /// This function will create a file if it does not exist, and will entirely replace its contents if it does.
    pub async fn write<P: AsRef<Path>, C: AsRef<[u8]>>(
        &mut self,
        path: P,
        contents: C,
    ) -> Result<()> {
        let path = path.as_ref();
        let contents = contents.as_ref();
        let (ssh, _) = self.get_ssh()?;

        let sftp = ssh.get_sftp().await?;
        let _ = sftp.create(path.to_string_lossy()).await?;
        sftp.write(path.to_string_lossy(), contents).await?;

        Ok(())
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        // Ensure QEMU process is killed
        if let Some(pid) = self.pid {
            let _ = std::process::Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .output();
        }
        // Clean up runtime files if configured to do so
        if self.config.clear {
            let dirs = QleanDirs::new().expect("Failed to get QleanDirs in Drop");
            let run_dir = dirs.runs.join(&self.id);
            let _ = std::fs::remove_dir_all(run_dir);
        }
    }
}
