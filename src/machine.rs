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
    KVM_AVAILABLE,
    image::Image,
    qemu::launch_qemu,
    ssh::{PersistedSshKeypair, Session, connect_ssh, get_ssh_key},
    utils::{CommandExt, HEX_ALPHABET, QleanDirs, gen_random_mac, get_free_cid},
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
    mac_address: String,
    ip: Option<String>,
}

#[derive(Clone)]
pub struct MachineImage {
    pub overlay: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub seed: PathBuf,
    pub root_arg: String,
    pub prefer_direct_kernel_boot: bool,
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

    /// Optional cloud-init directives used to configure the guest at first boot.
    ///
    /// We use these to enable an SSH listener on vhost-vsock so that Qlean can
    /// reach the guest without relying on TCP port forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_files: Option<Vec<CloudInitWriteFile>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub runcmd: Option<Vec<Vec<String>>>,

    /// Additional cloud-init configuration.
    ///
    /// This is intentionally a loose YAML value so we can support a mix of distro
    /// defaults (Ubuntu/Fedora/Arch) without encoding every schema detail in Rust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<serde_yml::Value>,

    /// Explicitly disable password authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_pwauth: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloudInitWriteFile {
    pub path: String,
    pub content: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
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

        // Enable an SSH path over vhost-vsock without requiring OpenSSH to accept an AF_VSOCK
        // socket directly.
        //
        // VSOCK-only (no TCP fallback): provide SSH access exclusively via vhost-vsock.
        //
        // We intentionally do NOT depend on the guest distro enabling/running sshd.service.
        // Instead, we use systemd socket activation and run `sshd -i` (inetd mode) for each
        // incoming vsock connection.
        //
        // IMPORTANT: StandardOutput must be wired to the socket; otherwise clients may connect
        // but never receive an SSH banner (hangs until handshake timeout).
        let sshd_wrapper = r#"#!/bin/sh
set -eu

for p in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do
  if [ -x "$p" ]; then
    exec "$p" "$@"
  fi
done

echo "qlean: sshd not found" >&2
exit 127
"#
        .to_string();

        let vsock_socket_unit = r#"[Unit]
Description=Qlean SSH over vhost-vsock (socket-activated sshd)

[Socket]
ListenStream=vsock::22
Accept=yes

[Install]
WantedBy=sockets.target
"#
        .to_string();

        let vsock_service_unit = r#"[Unit]
Description=Qlean SSH over vhost-vsock (per-connection sshd)

[Service]
ExecStart=/usr/bin/qlean-sshd-run -i -e \
  -o PermitRootLogin=yes \
  -o PasswordAuthentication=no \
  -o PubkeyAuthentication=yes \
  -o AuthorizedKeysFile=/root/.ssh/authorized_keys \
  -o StrictModes=yes
StandardInput=socket
StandardOutput=socket
StandardError=journal
"#
        .to_string();

        let user_data = UserData {
            disable_root: false,
            ssh_authorized_keys: vec![ssh_keypair.pubkey_str.clone()],
            write_files: Some(vec![
                CloudInitWriteFile {
                    path: "/etc/systemd/system/qlean-sshd-vsock.socket".to_string(),
                    content: vsock_socket_unit,
                    permissions: Some("0644".to_string()),
                    owner: Some("root:root".to_string()),
                },
                CloudInitWriteFile {
                    path: "/etc/systemd/system/qlean-sshd-vsock@.service".to_string(),
                    content: vsock_service_unit,
                    permissions: Some("0644".to_string()),
                    owner: Some("root:root".to_string()),
                },
                CloudInitWriteFile {
                    // /usr/bin is a safe location across distros, including SELinux-enforcing Fedora.
                    path: "/usr/bin/qlean-sshd-run".to_string(),
                    content: sshd_wrapper,
                    permissions: Some("0755".to_string()),
                    owner: Some("root:root".to_string()),
                },
                CloudInitWriteFile {
                    path: "/root/.ssh/authorized_keys".to_string(),
                    content: format!("{}\n", ssh_keypair.pubkey_str),
                    permissions: Some("0600".to_string()),
                    owner: Some("root:root".to_string()),
                },
            ]),
            runcmd: Some(vec![
                // Ensure the vsock transport exists in the guest.
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "modprobe vsock 2>/dev/null || true; modprobe vmw_vsock_virtio_transport 2>/dev/null || true; modprobe vhost_vsock 2>/dev/null || true".to_string(),
                ],
                // Ensure SSH host keys exist.
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "command -v ssh-keygen >/dev/null && ssh-keygen -A || true".to_string(),
                ],
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "systemctl daemon-reload".to_string(),
                ],
                // Fedora images commonly run with SELinux enforcing; permissive avoids rare policy
                // issues when starting our helper service.
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "if command -v getenforce >/dev/null && command -v setenforce >/dev/null; then if [ \"$(getenforce 2>/dev/null)\" = \"Enforcing\" ]; then setenforce 0 || true; fi; fi".to_string(),
                ],
                // Ensure sshd runtime dirs exist.
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "mkdir -p /run/sshd /root/.ssh && chmod 700 /root/.ssh || true".to_string(),
                ],
                // Enable the vsock sshd socket.
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "systemctl enable --now qlean-sshd-vsock.socket".to_string(),
                ],
                // Marker to simplify debugging via virt-cat.
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "echo qlean-cloud-init-ok > /var/log/qlean-cloud-init.marker || true".to_string(),
                ],
            ]),
            users: None,
            ssh_pwauth: Some(false),
        };
        let mut user_data_str = serde_yml::to_string(&user_data)?;
        user_data_str.insert_str(0, "#cloud-config\n");
        debug!("Writing cloud-init user-data:\n{}", user_data_str);
        tokio::fs::write(seed_dir.join("user-data"), user_data_str).await?;

        // cloud-init's NoCloud datasource expects both user-data and meta-data.
        // If meta-data is missing, many images will ignore the seed ISO entirely,
        // which means our SSH key and the vsock SSH proxy won't be configured.
        let meta_data = format!("instance-id: qlean-{}\nlocal-hostname: qlean\n", machine_id);
        tokio::fs::write(seed_dir.join("meta-data"), meta_data).await?;

        // Prepare seed ISO
        let seed_iso_path = run_dir.join("seed.iso");
        // NoCloud expects user-data/meta-data at the *root* of the ISO.
        // Passing the directory path directly would place it under /seed/ in the ISO, which
        // some distros do not detect (leading to missing SSH key/proxy setup).
        let user_data_path = seed_dir.join("user-data");
        let meta_data_path = seed_dir.join("meta-data");

        let mut xorriso_command = tokio::process::Command::new("xorriso");
        xorriso_command
            .args(["-as", "mkisofs"])
            .args(["-V", "cidata"])
            .args(["-J", "-R"])
            .args(["-o", seed_iso_path.to_str().unwrap()])
            .args(["-graft-points"])
            .arg(format!("user-data={}", user_data_path.to_string_lossy()))
            .arg(format!("meta-data={}", meta_data_path.to_string_lossy()));
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
            root_arg: image.root_arg().to_string(),
            prefer_direct_kernel_boot: image.prefer_direct_kernel_boot(),
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
            mac_address: gen_random_mac(),
            ip: None,
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
            // Then shut the system down. Try several commands because some cloud images
            // (notably Arch) log in as an unprivileged default user and plain
            // `systemctl poweroff` can fail with "Access denied".
            let shutdown_cmd = r#"sh -lc 'systemctl poweroff \
                || sudo -n systemctl poweroff \
                || sudo -n poweroff \
                || poweroff \
                || shutdown -h now \
                || sudo -n shutdown -h now'"#;
            if let Err(e) = ssh
                .call(
                    shutdown_cmd,
                    self.ssh_cancel_token
                        .as_ref()
                        .expect("Machine not initialized or spawned")
                        .clone(),
                )
                .await
            {
                // During shutdown the SSH session can drop before the command fully returns.
                // Keep going and rely on the QEMU process wait/cleanup below.
                debug!(
                    "Guest shutdown command returned error during teardown: {}",
                    e
                );
            }
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
            self.ip = None;

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
                    bail!("Download cancelled");
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

    /// Get the IP address of the machine
    pub async fn get_ip(&mut self) -> Result<String> {
        if let Some(ip) = &self.ip {
            Ok(ip.to_owned())
        } else {
            let (ssh, _) = self.get_ssh()?;
            let ip = ssh.get_remote_ip().await?;
            self.ip = Some(ip.to_owned());
            Ok(ip)
        }
    }

    /// Check if the machine is currently running
    pub(crate) async fn is_running(&self) -> Result<bool> {
        if let Some(pid) = self.pid {
            let process_exists = std::path::Path::new(&format!("/proc/{}", pid)).exists();
            let process_running = if process_exists {
                // Further check if the process is a QEMU process
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                    cmdline.contains("qemu-system")
                } else {
                    false
                }
            } else {
                false
            };
            Ok(process_running)
        } else {
            Ok(false)
        }
    }

    /// Launch QEMU and connect SSH concurrently
    async fn launch(&mut self, is_init: bool) -> Result<()> {
        debug!(
            "SSH command for manual debugging:\nssh root@vsock/{} -i {:?}",
            self.cid, self.keypair.privkey_path,
        );

        let kvm_available = KVM_AVAILABLE.get().copied().unwrap_or(false);
        // SSH reachability can be slow on first boot (cloud-init + sshd startup), especially on
        // slower disks or under nested virtualization.
        let ssh_timeout = if kvm_available {
            Duration::from_secs(180)
        } else {
            Duration::from_secs(300)
        };

        // Helper: read pid written by launch_qemu.
        async fn read_pid(vmid: &str) -> Result<u32> {
            let dirs = QleanDirs::new()?;
            let pid_file_path = dirs.runs.join(vmid).join("qemu.pid");

            // QEMU writes pid almost immediately after spawn; wait a short time to make cleanup reliable
            // even on slower filesystems.
            for _ in 0..50 {
                if let Ok(pid_str) = tokio::fs::read_to_string(&pid_file_path).await
                    && let Ok(pid) = pid_str.trim().parse::<u32>()
                {
                    return Ok(pid);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            bail!("Failed to read QEMU pid file at {:?}", pid_file_path);
        }

        // Helper: terminate QEMU process best-effort.
        async fn terminate_qemu(pid: u32) {
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .output();

            // Give it a moment to exit; then SIGKILL.
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = std::process::Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .output();
        }

        // Create a fresh cancellation token per launch.
        let launch_cancel = CancellationToken::new();
        self.ssh_cancel_token = Some(launch_cancel.clone());

        self.qemu_should_exit.store(false, Ordering::SeqCst);
        let qemu_params = crate::qemu::QemuLaunchParams {
            cid: self.cid,
            image: self.image.to_owned(),
            config: self.config.to_owned(),
            vmid: self.id.to_owned(),
            is_init,
            mac_address: self.mac_address.to_owned(),
            cancel_token: launch_cancel.clone(),
            expected_to_exit: self.qemu_should_exit.clone(),
        };

        let mut qemu_handle = tokio::spawn(launch_qemu(qemu_params));
        let pid = read_pid(&self.id).await?;
        self.pid = Some(pid);

        let mut ssh_handle = tokio::spawn(connect_ssh(
            self.cid,
            ssh_timeout,
            self.keypair.to_owned(),
            launch_cancel.clone(),
            self.mac_address.to_owned(),
        ));

        // Wait for SSH to complete, or abort SSH if QEMU errors.
        let ssh_result = tokio::select! {
            result = &mut ssh_handle => {
                result.map_err(|e| anyhow::anyhow!("SSH task panicked: {e}"))?
            }
            result = &mut qemu_handle => {
                // QEMU completed or errored, cancel SSH task.
                launch_cancel.cancel();
                match result {
                    Ok(Ok(())) => bail!("QEMU exited unexpectedly"),
                    Ok(Err(e)) => bail!(e),
                    Err(e) => bail!("QEMU task error: {e}"),
                }
            }
        };

        match ssh_result {
            Ok(session) => {
                self.ssh = Some(session);
                Ok(())
            }
            Err(e) => {
                // Ensure QEMU is torn down to avoid orphan processes.
                self.qemu_should_exit.store(true, Ordering::SeqCst);
                launch_cancel.cancel();
                if let Some(pid) = self.pid {
                    terminate_qemu(pid).await;
                }
                let _ = qemu_handle.await;
                bail!(e)
            }
        }
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
