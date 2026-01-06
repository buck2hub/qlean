use std::{
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Output,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

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
            return Err(anyhow::anyhow!(
                "Failed to create overlay image: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
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
            return Err(anyhow::anyhow!(
                "Failed to create seed ISO: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
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
                return Err(anyhow::anyhow!(
                    "Failed to resize image: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }

        if self.ssh_cancel_token.is_none() {
            self.ssh_cancel_token = Some(CancellationToken::new());
        } else {
            return Err(anyhow::anyhow!("Machine already initialized"));
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
            return Err(anyhow::anyhow!("Machine already spawned"));
        }

        self.launch(false).await?;

        Ok(())
    }

    /// Execute a command on the machine and return the output
    pub async fn exec(&mut self, cmd: &str) -> Result<Output> {
        info!("🧬 Executing command `{}` on VM-{}", cmd, self.id);
        if let Some(ssh) = self.ssh.as_mut() {
            let cancel_token = self
                .ssh_cancel_token
                .as_ref()
                .expect("Machine not initialized or spawned")
                .clone();

            let (exit_code, stdout, stderr) = ssh.call_with_output(cmd, cancel_token).await?;

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

    async fn launch(&mut self, is_init: bool) -> Result<()> {
        debug!(
            "SSH command for manual debugging:\nssh root@vsock/{} -i {:?}",
            self.cid, self.keypair.privkey_path,
        );

        // Launch QEMU and connect SSH concurrently
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
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(anyhow::anyhow!("SSH task panicked: {}", e)),
                }
            }
            result = qemu_handle => {
                // QEMU completed or errored, cancel SSH task
                self.ssh_cancel_token.as_ref().expect("Machine not initialized or spawned").cancel();
                match result {
                    Ok(Err(e)) => return Err(e),
                    Ok(Ok(())) => return Err(anyhow::anyhow!("QEMU exited unexpectedly")),
                    Err(e) => return Err(anyhow::anyhow!("QEMU task error: {}", e)),
                }
            }
        }

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
