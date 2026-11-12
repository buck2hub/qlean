use std::{
    borrow::Cow,
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Output,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use nanoid::nanoid;
use russh_sftp::client::fs::{Metadata, ReadDir};
use serde::{Deserialize, Serialize};
use shell_escape::unix::escape;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::{
    firmware::{self, Swtpm, VmFirmware},
    guest_path::{GuestPath, PosixOnlyOperation, ensure_supported},
    image::{GuestArch, GuestOs, Image},
    is_kvm_available,
    qemu::launch_qemu,
    qmp,
    ssh::{
        InteractiveShell, PersistedSshKeypair, Session, connect_ssh, connect_ssh_windows,
        get_ssh_key,
    },
    utils::{CommandExt, HEX_ALPHABET, QleanDirs, gen_random_mac, get_free_cid},
    windows::{self, DeploySeed},
};

/// Virtual machine.
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
    /// Software TPM backing a Windows guest's TPM 2.0 device.
    swtpm: Option<Swtpm>,
    /// First-boot deployment medium for a Windows guest, deleted once the guest
    /// confirms the deployment.
    deploy_seed: Option<DeploySeed>,
    /// Public half of the per-VM SSH host key (Windows guests only), kept on the
    /// host so the transport can pin it instead of trusting the first key seen.
    ssh_host_key: Option<String>,
    /// Deadline shared by every phase of a Windows first boot.
    ///
    /// The documented deployment budget bounds the *whole* first boot: waiting for the
    /// DHCP lease, waiting for `sshd` and waiting for the deploy marker. Giving each
    /// phase a fresh budget would allow three times the documented wait, so the phases
    /// share one deadline. `None` means no first boot is in progress.
    first_boot_deadline: Option<std::time::Instant>,
}

/// Removes a half-built run directory unless construction completed.
///
/// [`Machine::new`] creates the run directory, the disk overlay, the SSH host key and (for
/// Windows) the seed medium before it can return. If any of those steps fails the caller
/// gets an error and no `Machine`, so `Drop` would never clean up: without this guard a
/// failed construction leaves a directory, an overlay and seed material behind in `runs/`
/// that nothing ever removes.
struct RunDirGuard {
    path: PathBuf,
    armed: bool,
}

impl RunDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    /// Keep the directory: construction finished and the `Machine` owns it now.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for RunDirGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        warn!(
            "removing the partially built run directory {} after a failed construction",
            self.path.display()
        );
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            warn!(
                "failed to remove the partially built run directory {}: {error}",
                self.path.display()
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct MachineImage {
    pub overlay: PathBuf,
    pub arch: GuestArch,
    pub guest_os: GuestOs,
    pub seed: PathBuf,
}

/// Configuration for a virtual machine.
#[derive(Clone, Debug)]
pub struct MachineConfig {
    /// Number of CPU cores, defaults to `2`.
    pub core: u32,
    /// Memory in MB, defaults to `4096`.
    pub mem: u32,
    /// Disk size in GB, defaults to `None`. If provided, the image will be resized to the specified size.
    pub disk: Option<u32>,
    /// Whether to clear the runtime directory after use, defaults to `true`.
    pub clear: bool,
    /// Timeout in seconds for SSH over vsock to wait during launch, defaults to `180` with KVM and `300` under TCG.
    pub ssh_timeout: Option<u64>,
}

impl MachineConfig {
    /// Set the number of CPU cores.
    pub fn with_core(self, core: u32) -> Self {
        Self { core, ..self }
    }

    /// Set the memory in MB.
    pub fn with_mem(self, mem: u32) -> Self {
        Self { mem, ..self }
    }

    /// Set the disk size in GB.
    pub fn with_disk(self, disk: u32) -> Self {
        Self {
            disk: Some(disk),
            ..self
        }
    }

    /// Set the timeout in seconds for SSH over vsock to wait during launch.
    pub fn with_timeout(self, ssh_timeout: u64) -> Self {
        Self {
            ssh_timeout: Some(ssh_timeout),
            ..self
        }
    }

    /// Set whether to clear the runtime directory after use.
    pub fn with_clear(self, clear: bool) -> Self {
        Self { clear, ..self }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct MetaData {
    #[serde(rename = "instance-id")]
    pub instance_id: String,
    #[serde(rename = "local-hostname")]
    pub local_hostname: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserData {
    pub disable_root: bool,
    pub ssh_authorized_keys: Vec<String>,

    /// Optional cloud-init directives used to configure the guest at first boot.
    ///
    /// We use these to enable an SSH listener on vhost-vsock so that Qlean can reach the guest without relying on TCP port forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_files: Option<Vec<CloudInitWriteFile>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub runcmd: Option<Vec<Vec<String>>>,

    /// Additional cloud-init configuration.
    ///
    /// This is intentionally a loose YAML value so we can support a mix of distro defaults (Ubuntu/Fedora/Arch) without encoding every schema detail in Rust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<serde_yml::Value>,

    /// Explicitly disable password authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_pwauth: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CloudInitWriteFile {
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
            ssh_timeout: None,
        }
    }
}

/// Resolve a Windows guest's SSH endpoint from its DHCP lease.
///
/// The address comes from the libvirt DHCP lease for this VM's MAC, so it never relies on
/// running a command inside the guest. Owned inputs keep the returned future free of a
/// borrow on `Machine`, which the caller needs for cleanup in the racing branches.
async fn discover_windows_endpoint(
    mac_address: String,
    ssh_host_key: Option<String>,
    timeout: Duration,
) -> Result<(std::net::SocketAddr, String)> {
    let host_key = ssh_host_key.ok_or_else(|| {
        anyhow::anyhow!(
            "Windows guest is missing its per-VM SSH host key; the deployment seed was not staged"
        )
    })?;
    let ip = crate::utils::find_lease_address(&mac_address, timeout).await?;
    Ok((std::net::SocketAddr::new(ip, windows::SSH_PORT), host_key))
}

/// Connection budget for `Machine::launch`.
///
/// A Windows guest's first boot must also finish its deployment before `sshd`
/// answers, and that work is budgeted by `windows::deploy_timeout` (900s by
/// default). Using the plain connect budget there would abort a working first
/// boot at 180s, leaving the deployment budget unreachable. Later boots and
/// Linux guests keep the historical connect budget.
fn resolve_connect_timeout(config: &MachineConfig, guest_os: GuestOs, is_init: bool) -> Duration {
    if guest_os == GuestOs::Windows && is_init {
        return windows::deploy_timeout(config);
    }
    resolve_ssh_timeout(config)
}

/// What is left of a shared deadline, or `None` once it has passed.
fn remaining_budget(deadline: std::time::Instant) -> Option<Duration> {
    let now = std::time::Instant::now();
    (deadline > now).then(|| deadline - now)
}

/// Message for a first boot that used up its deployment budget before `phase`.
fn spent_first_boot_budget(phase: &str, budget: Duration) -> anyhow::Error {
    anyhow::anyhow!(
        "the Windows first boot used its whole {}s deployment budget before {phase}.\n\
         The budget covers the entire first boot (DHCP lease, `sshd`, deploy marker), not one \
         phase, so a later phase gets no fresh wait. Raise `MachineConfig::ssh_timeout` if this \
         image genuinely needs longer; see the README \"Windows image contract\"",
        budget.as_secs()
    )
}

fn resolve_ssh_timeout(config: &MachineConfig) -> Duration {
    config
        .ssh_timeout
        .map(Duration::from_secs)
        .unwrap_or_else(|| {
            if is_kvm_available() {
                Duration::from_secs(180)
            } else {
                Duration::from_secs(300)
            }
        })
}

// Core methods for Machine
impl Machine {
    /// Create a new Machine instance with specified image and configuration.
    pub async fn new(image: &Image, config: &MachineConfig) -> Result<Self> {
        // Prepare run directory
        let dirs = QleanDirs::new()?;
        let machine_id = nanoid!(12, &HEX_ALPHABET);
        let run_dir = Path::new(&dirs.runs).join(&machine_id);
        let seed_dir = run_dir.join("seed");
        tokio::fs::create_dir_all(&run_dir).await?;
        tokio::fs::create_dir_all(&seed_dir).await?;
        // The run directory holds the per-VM host private key, the seed medium and the
        // disk overlay: keep it owner-only regardless of the host umask.
        crate::utils::restrict_dir(&run_dir)?;
        // Everything below writes into `run_dir`; if it fails, the directory must not
        // outlive the failed construction.
        let run_dir_guard = RunDirGuard::new(run_dir.clone());

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

        // Windows guests follow ADR-WIN-03: a pre-generalized image plus a per-VM
        // seed medium, instead of cloud-init NoCloud user-data.
        if image.guest_os() == GuestOs::Windows {
            // Fail before generating keys or building the seed medium: a host that cannot
            // run the guest must not leave seed material or an ISO behind.
            firmware::ensure_host_support()?;
            let host_key = windows::generate_host_key(&run_dir)?;
            let seed =
                DeploySeed::stage(&run_dir, ssh_keypair.pubkey_str.trim(), &host_key).await?;
            seed.build().await?;
            let seed_iso_path = seed.iso_path().to_path_buf();

            let machine_image = MachineImage {
                overlay: overlay_image,
                arch: image.guest_arch(),
                guest_os: image.guest_os(),
                seed: seed_iso_path,
            };

            run_dir_guard.disarm();
            return Ok(Self {
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
                swtpm: None,
                deploy_seed: Some(seed),
                ssh_host_key: Some(host_key.pubkey_str.trim().to_string()),
                first_boot_deadline: None,
            });
        }

        // Prepare cloud-init config
        let meta_data = MetaData {
            instance_id: format!("VM-{}", machine_id),
            local_hostname: "qlean-vm".to_string(),
        };
        let mut meta_data_str = serde_yml::to_string(&meta_data)?;
        meta_data_str.insert_str(0, "#cloud-config\n");
        debug!("Writing cloud-init meta-data:\n{}", meta_data_str);
        tokio::fs::write(seed_dir.join("meta-data"), meta_data_str).await?;

        // Enable an SSH path over vhost-vsock without requiring OpenSSH to accept an AF_VSOCK socket directly.
        //
        // We intentionally do NOT depend on the guest distro enabling/running sshd.service.
        // Instead, we use systemd socket activation and run `sshd -i` (inetd mode) for each incoming vsock connection.
        //
        // IMPORTANT: StandardOutput must be wired to the socket; otherwise clients may connect but never receive an SSH banner (hangs until handshake timeout).
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
            // `-o` takes the path as its own argument, so no string conversion is needed.
            .arg("-o")
            .arg(&seed_iso_path)
            .arg("-graft-points")
            .arg(crate::utils::path_argument("user-data=", &user_data_path))
            .arg(crate::utils::path_argument("meta-data=", &meta_data_path));
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
            arch: image.guest_arch(),
            guest_os: image.guest_os(),
            seed: seed_iso_path,
        };

        run_dir_guard.disarm();
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
            swtpm: None,
            deploy_seed: None,
            ssh_host_key: None,
            first_boot_deadline: None,
        })
    }

    /// Initialize the machine (first boot with cloud-init).
    ///
    /// A Windows guest may only be initialized once: its first boot consumes the seed
    /// medium, which is deleted once the deployment marker appears. A second `init`
    /// would boot without a seed (and without the host key the guest installed), so it
    /// is rejected here instead of failing later inside QEMU or at the host-key check.
    pub async fn init(&mut self) -> Result<()> {
        if self.image.guest_os == GuestOs::Windows && self.deploy_seed.is_none() {
            bail!(
                "VM-{} already completed its Windows first-boot deployment; use `spawn` to start it again",
                self.id
            );
        }
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

        // Same rule as `spawn`: a leftover token from a failed launch must not block a retry.
        if self.ssh_cancel_token.is_some() && (self.pid.is_some() || self.ssh.is_some()) {
            bail!("Machine already initialized");
        }
        self.ssh_cancel_token = Some(CancellationToken::new());

        if let Err(err) = self.launch(true).await {
            self.abandon_launch();
            return Err(err);
        }

        Ok(())
    }

    /// Whether starting this machine should run `init` rather than `spawn`.
    ///
    /// A Linux guest can be initialized repeatedly (a fresh cloud-init seed each time). A
    /// Windows guest consumes its deployment seed exactly once, so after the first boot it
    /// can only be spawned; calling `init` again is rejected by design.
    pub(crate) fn wants_init(&self) -> bool {
        self.image.guest_os != GuestOs::Windows || self.needs_first_boot()
    }

    /// Whether this machine has a Windows deployment that has not run yet.
    ///
    /// Starting such a machine with `spawn` would boot a guest whose `sshd` has no
    /// installed key, so the deployment has to run first.
    pub(crate) fn needs_first_boot(&self) -> bool {
        self.image.guest_os == GuestOs::Windows && self.deploy_seed.is_some()
    }

    /// Spawn the machine (normal boot).
    pub async fn spawn(&mut self) -> Result<()> {
        info!("🔥 Spawning VM-{}", self.id);

        // Only a machine that is actually up counts as spawned: a failed launch leaves
        // the token behind, and refusing to retry would make the error unrecoverable.
        if self.ssh_cancel_token.is_some() && (self.pid.is_some() || self.ssh.is_some()) {
            bail!("Machine already spawned");
        }
        spawn_guard(self.needs_first_boot(), &self.id)?;
        self.ssh_cancel_token = Some(CancellationToken::new());

        if let Err(err) = self.launch(false).await {
            self.abandon_launch();
            return Err(err);
        }

        Ok(())
    }

    /// Drop the cancel token of a launch that failed, so the machine can be retried.
    ///
    /// The token also serves as the "this machine was started" marker, so it has to be
    /// cancelled (to stop any leftover connection task) and cleared; otherwise the next
    /// `init`/`spawn` would report "already initialized" for a machine that never started.
    fn abandon_launch(&mut self) {
        if let Some(token) = self.ssh_cancel_token.take() {
            token.cancel();
        }
        self.ssh = None;
        self.ip = None;
    }

    /// Open a dedicated interactive SSH shell (PTY) over a new vsock session.
    ///
    /// Does not use or block the management SSH session used by `exec` / upload.
    /// Requires the machine to already be running (`ssh` and `pid` set after init/spawn).
    pub async fn open_interactive_shell(&self, cols: u32, rows: u32) -> Result<InteractiveShell> {
        if self.image.guest_os == GuestOs::Windows {
            // There is no vsock endpoint to open a second session on, and a
            // half-created TCP Pty would leak a process. Report it plainly instead.
            bail!(
                "Interactive PTY shells are not supported for Windows guests; use `exec` to run \
                 commands and SFTP upload/download for file transfer"
            );
        }

        if self.ssh.is_none() || self.pid.is_none() {
            bail!(
                "Machine is not running; initialize or spawn before opening an interactive shell"
            );
        }

        let Some(cancel) = self.ssh_cancel_token.as_ref().cloned() else {
            bail!(
                "Machine is not running; initialize or spawn before opening an interactive shell"
            );
        };

        let session = connect_ssh(
            self.cid,
            resolve_ssh_timeout(&self.config),
            self.keypair.clone(),
            cancel.clone(),
            self.mac_address.clone(),
        )
        .await?;

        session.open_shell(cols, rows, cancel).await
    }

    /// Execute a command on the machine and return the output.
    ///
    /// The command string is passed through verbatim: Linux guests run it in their
    /// configured shell, Windows guests in PowerShell (see `README`), and no argument
    /// escaping is applied on either path.
    pub async fn exec<S: AsRef<str>>(&mut self, cmd: S) -> Result<Output> {
        let cmd_ref = cmd.as_ref();
        if cmd_ref.trim().is_empty() {
            bail!(
                "`exec` requires a non-empty command; an empty string would be sent as an empty shell request with no defined result"
            );
        }
        info!("🧬 Executing command `{}` on VM-{}", cmd_ref, self.id);
        let (ssh, cancel_token) = self.get_ssh("run a command")?;
        let (exit_code, stdout, stderr) = ssh.call_with_output(cmd_ref, cancel_token).await?;

        Ok(Output {
            status: crate::exec::exit_status_from_code(cmd_ref, exit_code)?,
            stdout,
            stderr,
        })
    }

    /// Shutdown the machine.
    pub async fn shutdown(&mut self) -> Result<()> {
        if self.pid.is_none() && self.ssh.is_none() {
            bail!("Machine is not running");
        }

        info!("🔌 Shutting down VM-{}", self.id);

        if self.pid.is_some() {
            let socket_path = qmp::qmp_socket_path(&self.id)?;
            if let Err(e) = qmp::powerdown(&socket_path).await {
                // The guest will be killed instead of shut down: say why, at a level the
                // user sees, because the diagnostic below only mentions the timeout.
                warn!("could not ask the guest to power down, it may be killed instead: {e:#}");
            }
        }

        self.qemu_should_exit.store(true, Ordering::SeqCst);

        if let Some(ssh) = self.ssh.as_mut() {
            let _ = ssh.close().await;
        }

        if let Some(pid) = self.pid {
            debug!("Waiting for QEMU process {} to exit", pid);
            let max_wait_time = Duration::from_secs(30);
            let poll_interval = Duration::from_millis(100);
            let start = std::time::Instant::now();
            let mut kill_sent = false;

            loop {
                let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
                match teardown_step(alive, start.elapsed(), max_wait_time, kill_sent) {
                    TeardownStep::StillGone => {
                        debug!("QEMU process {} has exited", pid);
                        break;
                    }
                    TeardownStep::KeepWaiting => {
                        tokio::time::sleep(poll_interval).await;
                    }
                    TeardownStep::ForceKill => {
                        info!(
                            "QEMU process {} did not exit within timeout, force killing",
                            pid
                        );
                        if kill_if_qemu(pid) {
                            kill_sent = true;
                        } else {
                            // The pid no longer belongs to our QEMU, so there is nothing left
                            // for teardown to wait for.
                            break;
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    TeardownStep::Unkillable => {
                        // Leave `self.pid` set: the process is still running, so reporting a
                        // clean shutdown would let the next start rebuild the overlay of a
                        // live guest.
                        bail!(
                            "QEMU process {pid} is still running after SIGKILL: the machine was not shut down.                              Kill pid {pid} manually before starting it again"
                        );
                    }
                }
            }
        }

        if let Some(mut swtpm) = self.swtpm.take() {
            swtpm.stop().await;
        }

        let dirs = QleanDirs::new()?;
        let pid_file_path = dirs.runs.join(&self.id).join("qemu.pid");
        let _ = tokio::fs::remove_file(pid_file_path).await;
        self.ssh = None;
        self.pid = None;
        self.ssh_cancel_token = None;
        self.ip = None;

        Ok(())
    }

    /// Upload file or directory to the machine.
    ///
    /// Remote paths are always built as `GuestPath` values, so a Windows drive path is never
    /// reinterpreted as a host path. Uploading a tree that contains a symbolic link fails
    /// instead of silently skipping the link.
    pub async fn upload<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        local_path: P,
        remote_path: Q,
    ) -> Result<()> {
        let local_path = local_path.as_ref();
        let os = self.image.guest_os;
        let remote_path = guest_path_from(os, remote_path.as_ref())?;
        info!(
            "📤 Uploading {:?} to {} on VM-{}",
            local_path,
            remote_path.as_str(),
            self.id
        );
        let (ssh, cancel_token) = self.get_ssh("upload files")?;

        let meta = tokio::fs::metadata(local_path).await?;
        if meta.is_file() {
            // Decide final remote target path (dir vs file path)
            let remote_target = {
                let is_dir = {
                    let sftp = ssh.get_sftp().await?;
                    sftp.read_dir(remote_path.as_str()).await.is_ok()
                };
                if is_dir {
                    remote_path.join(local_basename(local_path)?)?
                } else {
                    remote_path.clone()
                }
            };

            // Ensure remote parent directory exists
            if let Some(parent) = remote_target.parent() {
                ssh.create_dir_all(&parent).await?;
            }

            ssh.upload_file(local_path, &remote_target, cancel_token.clone())
                .await?;
        } else if meta.is_dir() {
            // For directory: mirror into remote_path/<basename>
            let remote_root = remote_path.join(local_basename(local_path)?)?;
            ssh.create_dir_all(&remote_root).await?;

            for entry in WalkDir::new(local_path).follow_links(false) {
                let entry = entry?;
                let ty = entry.file_type();

                // Cancellation check
                if cancel_token.is_cancelled() {
                    bail!("Upload cancelled");
                }

                // Relative path under local_path, converted to a guest path
                let rel = entry.path().strip_prefix(local_path).with_context(|| {
                    format!(
                        "failed to derive the relative path of {:?} under {local_path:?}",
                        entry.path()
                    )
                })?;
                let remote_entry = remote_root.join(rel.to_string_lossy())?;

                if ty.is_dir() {
                    ssh.create_dir_all(&remote_entry).await?;
                } else if ty.is_file() {
                    if let Some(parent) = remote_entry.parent() {
                        ssh.create_dir_all(&parent).await?;
                    }
                    ssh.upload_file(entry.path(), &remote_entry, cancel_token.clone())
                        .await?;
                } else if ty.is_symlink() {
                    if os == GuestOs::Windows {
                        bail!(
                            "symbolic links are not supported when uploading to a Windows guest: {}",
                            remote_entry.as_str()
                        );
                    }
                    // Recreate the link (Linux guests only). A failure here must not be
                    // reported as a successful upload.
                    let target = tokio::fs::read_link(entry.path()).await.with_context(|| {
                        format!("failed to read the link at {:?}", entry.path())
                    })?;
                    if let Some(parent) = remote_entry.parent() {
                        ssh.create_dir_all(&parent).await?;
                    }
                    {
                        let sftp = ssh.get_sftp().await?;
                        sftp.symlink(remote_entry.as_str(), target.to_string_lossy())
                            .await
                            .with_context(|| {
                                format!(
                                    "failed to recreate the symbolic link {}",
                                    remote_entry.as_str()
                                )
                            })?;
                    }
                } else {
                    bail!(
                        "unsupported filesystem entry while uploading {:?}: only files, directories and (Linux) symbolic links are supported",
                        entry.path()
                    );
                }
            }
        } else {
            bail!("Unsupported local path type");
        }

        Ok(())
    }

    /// Download file or directory from the machine.
    ///
    /// The remote side is traversed with `GuestPath` semantics; entries that cannot be
    /// represented (for example symbolic links, which SFTP cannot fetch as links) are
    /// reported as errors instead of being skipped silently.
    pub async fn download<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        remote_path: P,
        local_path: Q,
    ) -> Result<()> {
        let local_path = local_path.as_ref();
        let os = self.image.guest_os;
        let remote_path = guest_path_from(os, remote_path.as_ref())?;
        info!(
            "📥 Downloading {} from VM-{} to {:?}",
            remote_path.as_str(),
            self.id,
            local_path
        );
        let (ssh, cancel_token) = self.get_ssh("download files")?;

        // Check remote path type
        let remote_meta = {
            let sftp = ssh.get_sftp().await?;
            sftp.metadata(remote_path.as_str()).await.map_err(|e| {
                anyhow::anyhow!("Failed to stat remote path {}: {}", remote_path.as_str(), e)
            })?
        };

        if !remote_meta.is_dir() {
            // Decide final local target path (dir vs file path)
            let local_target = match tokio::fs::metadata(local_path).await {
                Ok(attr) if attr.is_dir() => {
                    let name = remote_path.file_name().ok_or_else(|| {
                        anyhow::anyhow!(
                            "remote path {} has no basename to reuse",
                            remote_path.as_str()
                        )
                    })?;
                    local_path.join(name)
                }
                _ => local_path.to_path_buf(),
            };

            // Ensure local parent directory exists
            if let Some(parent) = local_target.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    anyhow::anyhow!("Failed to create local directory {:?}: {}", parent, e)
                })?;
            }

            ssh.download_file(&remote_path, &local_target, cancel_token.clone())
                .await?;
        } else if remote_meta.is_dir() {
            // For directory: mirror into local_path/<basename>
            let base = remote_path.file_name().ok_or_else(|| {
                anyhow::anyhow!(
                    "remote path {} has no basename to reuse",
                    remote_path.as_str()
                )
            })?;
            let local_root = local_path.join(base);
            tokio::fs::create_dir_all(&local_root).await.map_err(|e| {
                anyhow::anyhow!("Failed to create local directory {:?}: {}", local_root, e)
            })?;

            // Use walk_remote_dir for DFS traversal
            let entries = ssh
                .walk_remote_dir(
                    &remote_path,
                    /*follow_links=*/ false,
                    cancel_token.clone(),
                )
                .await?;

            for e in entries {
                if cancel_token.is_cancelled() {
                    bail!("Download cancelled");
                }

                // Compute local path relative to the remote root
                let rel = e.path().strip_prefix(&remote_path).ok_or_else(|| {
                    anyhow::anyhow!(
                        "remote entry {} is not under {}",
                        e.path().as_str(),
                        remote_path.as_str()
                    )
                })?;
                let local_entry = if rel.is_empty() {
                    local_root.clone()
                } else {
                    local_root.join(rel)
                };

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
                    bail!(
                        "cannot download the symbolic link {} as a link; download its target instead",
                        e.path().as_str()
                    );
                } else {
                    bail!(
                        "unsupported filesystem entry while downloading {}",
                        e.path().as_str()
                    );
                }
            }
        } else {
            bail!("Unsupported remote path type");
        }

        Ok(())
    }

    /// Helper to get SSH session and cancellation token
    fn get_ssh(&mut self, operation: &str) -> Result<(&mut Session, CancellationToken)> {
        let machine_id = self.id.clone();
        session_or_operation_error(
            &mut self.ssh,
            self.ssh_cancel_token.as_ref(),
            operation,
            &machine_id,
        )
    }

    /// Public half of this machine's SSH host key, if the guest uses a per-VM one.
    ///
    /// Windows guests get a fresh host keypair per VM; the public half is returned
    /// here so the transport can pin it instead of trusting an unseen key.
    pub fn ssh_host_key(&self) -> Option<&str> {
        self.ssh_host_key.as_deref()
    }

    /// Wait for a Windows guest's first-boot deployment, then drop the seed medium.
    ///
    /// The guest-side marker is only observable over an established session, so this
    /// is a no-op for Linux guests and for Windows guests that have not connected
    /// yet. On success the seed ISO and its staged directory are deleted, so later
    /// boots can never re-read the client public key.
    pub(crate) async fn confirm_deployment(&mut self) -> Result<()> {
        if self.image.guest_os != GuestOs::Windows || self.deploy_seed.is_none() {
            return Ok(());
        }

        let timeout = windows::deploy_timeout(&self.config);
        let start = std::time::Instant::now();
        // A first boot that is still running shares one deadline with the lease and `sshd`
        // waits, so the documented budget bounds the whole boot instead of one phase.
        let remaining = self
            .first_boot_deadline
            .and_then(remaining_budget)
            .unwrap_or(timeout);
        // A marker poll that cannot reach the guest says nothing about deployment: the
        // session may have died because the guest rebooted. Retrying that for the whole
        // budget would report "deployment did not finish" 15 minutes later, so give up
        // after a few consecutive transport failures with an actionable message.
        const MAX_CONSECUTIVE_TRANSPORT_ERRORS: u32 = 3;
        let mut transport_errors = 0;
        loop {
            match self.deploy_marker_present().await {
                Ok(true) => break,
                Ok(false) => transport_errors = 0,
                Err(e) => {
                    transport_errors += 1;
                    if transport_errors >= MAX_CONSECUTIVE_TRANSPORT_ERRORS {
                        return Err(e).with_context(|| {
                            format!(
                                "lost the SSH session to VM-{} while waiting for the Windows \
                                 deployment marker; the guest probably rebooted or stopped sshd. \
                                 Retry with `spawn` once the guest is reachable again",
                                self.id
                            )
                        });
                    }
                }
            }
            if start.elapsed() >= remaining {
                bail!("{}", windows::deploy_timeout_message(timeout));
            }
            tokio::time::sleep(windows::DEPLOY_POLL_INTERVAL).await;
        }

        if let Some(seed) = self.deploy_seed.take() {
            let iso = seed.iso_path().to_path_buf();
            match seed.remove().await {
                Ok(()) => debug!("VM-{} deployed; seed medium removed", self.id),
                // The guest is deployed and the machine is usable: a leftover seed file
                // must not turn a successful first boot into a failure. It stays inside
                // the owner-only run directory, so report it and move on.
                Err(e) => warn!(
                    "VM-{} deployed, but the seed medium {iso:?} could not be removed: {e:#}",
                    self.id
                ),
            }
        }
        Ok(())
    }

    /// Whether the guest reports that its first-boot deployment finished.
    ///
    /// `Ok(false)` means the guest answered and the marker is absent; `Err` means the
    /// question could not be asked, which must not be mistaken for "not deployed yet".
    async fn deploy_marker_present(&mut self) -> Result<bool> {
        marker_probe_guard(
            self.ssh.is_some() && self.ssh_cancel_token.is_some(),
            &self.id,
        )?;
        let Some(cancel_token) = self.ssh_cancel_token.clone() else {
            bail!(
                "internal inconsistency: VM-{} has a session but no cancellation token",
                self.id
            );
        };
        let Some(ssh) = self.ssh.as_mut() else {
            bail!(
                "internal inconsistency: VM-{} was reported reachable without a session",
                self.id
            );
        };
        let cmd = format!(
            "cmd /c if exist {} echo deployed",
            windows::GUEST_DEPLOY_MARKER
        );
        let (code, stdout, stderr) = ssh.call_probe(&cmd, cancel_token).await?;
        if code != 0 {
            bail!(
                "deployment marker probe `{cmd}` exited with {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&stdout).contains("deployed"))
    }

    /// Guest operating system family of this machine's image.
    ///
    /// This is the single source of truth for OS-dependent behavior (deployment,
    /// transport, command shell); do not re-derive it from the image name.
    pub fn guest_os(&self) -> GuestOs {
        self.image.guest_os
    }

    /// Get the IP address of the machine.
    pub async fn get_ip(&mut self) -> Result<String> {
        if let Some(ip) = &self.ip {
            return Ok(ip.to_owned());
        }

        let ip = if self.image.guest_os == GuestOs::Windows {
            // Windows guests are reached over the NAT network: the address Qlean used for
            // the transport is the authoritative one, and a re-query must confirm the same
            // MAC instead of falling back to `hostname -I` or another VM's lease.
            self.query_windows_ip().await?
        } else {
            let (ssh, _) = self.get_ssh("query the guest address")?;
            ssh.get_remote_ip().await?
        };
        self.ip = Some(ip.to_owned());
        Ok(ip)
    }

    /// Ask a Windows guest for its own address and match it against this VM's MAC.
    async fn query_windows_ip(&mut self) -> Result<String> {
        let (ssh, cancel_token) = self.get_ssh("query the guest address")?;
        let (code, stdout, stderr) = ssh
            .call_probe(windows::GUEST_IP_QUERY, cancel_token)
            .await?;
        if code != 0 {
            bail!(
                "failed to query the Windows guest address (exit code {code}): {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }

        let addresses = windows::parse_adapter_addresses(&String::from_utf8_lossy(&stdout));
        let ip = windows::select_guest_address(&addresses, &self.mac_address)?;
        Ok(ip.to_string())
    }

    /// Check if the machine is currently running.
    ///
    /// A failed QMP query is reported instead of being folded into `false`: the callers use
    /// `false` to decide that a launch is safe, and starting a second QEMU on a live domain's
    /// disk would corrupt it. Only a missing socket is proof that the domain is gone.
    pub async fn is_running(&self) -> Result<bool> {
        let socket_path = qmp::qmp_socket_path(&self.id)?;
        match running_check(self.pid.is_some(), socket_path.exists()) {
            RunningCheck::NotRunning => Ok(false),
            RunningCheck::NoControlSocket => Ok(false),
            RunningCheck::AskQmp => qmp::query_running(&socket_path).await.with_context(|| {
                format!(
                    "VM-{} has a QEMU pid and a QMP socket at {} but the control socket did not \
                     answer; check whether the process is still alive before starting it again",
                    self.id,
                    socket_path.display()
                )
            }),
        }
    }

    /// Launch QEMU and connect SSH concurrently.
    async fn launch(&mut self, is_init: bool) -> Result<()> {
        debug!(
            "SSH command for manual debugging:\nssh root@vsock/{} -i {:?}",
            self.cid, self.keypair.privkey_path,
        );

        let ssh_timeout = resolve_connect_timeout(&self.config, self.image.guest_os, is_init);
        // One deadline for the whole Windows first boot: the lease wait, the `sshd` wait and
        // the deploy-marker wait draw from the same budget instead of starting fresh each
        // time. Later boots keep the plain connect budget with no shared deadline.
        self.first_boot_deadline = (is_init && self.image.guest_os == GuestOs::Windows)
            .then(|| std::time::Instant::now() + ssh_timeout);

        // Helper: read pid written by launch_qemu.
        async fn read_pid(vmid: &str) -> Result<u32> {
            let dirs = QleanDirs::new()?;
            let pid_file_path = dirs.runs.join(vmid).join("qemu.pid");

            // QEMU writes pid almost immediately after spawn; wait a short time to make cleanup reliable even on slower filesystems.
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
            if !process_is_qemu(pid) {
                warn!("QEMU pid {pid} is gone; nothing to terminate");
                return;
            }
            if let Err(error) = signal_term(pid) {
                warn!("failed to send SIGTERM to QEMU pid {pid}: {error}");
            }

            // Give it a moment to exit; then SIGKILL.
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            kill_if_qemu(pid);
        }

        // `launch` is only reached through `init`/`spawn`, which set the token; check
        // instead of panicking so a future caller cannot turn this into a crash.
        let Some(cancel_token) = self.ssh_cancel_token.clone() else {
            bail!(
                "cannot launch VM-{}: it has no SSH cancellation token because `init` or `spawn` \
                 was not reached; use those entry points instead of launching directly",
                self.id
            );
        };
        self.qemu_should_exit.store(false, Ordering::SeqCst);
        // Windows guests need OVMF (per-VM vars) and a TPM 2.0 backed by swtpm.
        let mut machine_firmware: Option<VmFirmware> = None;
        let mut tpm_socket: Option<PathBuf> = None;
        if self.image.guest_os == GuestOs::Windows {
            firmware::ensure_host_support()?;
            let dirs = QleanDirs::new()?;
            let run_dir = dirs.runs.join(&self.id);
            tokio::fs::create_dir_all(&run_dir).await?;
            let resolved = firmware::resolve_ovmf()?;
            let vars = firmware::prepare_vars(&run_dir, &resolved)?;
            if self.swtpm.is_none() {
                self.swtpm = Some(Swtpm::start(&run_dir).await?);
            }
            let socket = match self.swtpm.as_ref() {
                Some(swtpm) => swtpm.socket().to_path_buf(),
                None => bail!(
                    "cannot launch VM-{}: the software TPM was not started, so the guest has no \
                     TPM 2.0 device; re-run `spawn` after `swtpm` is available",
                    self.id
                ),
            };
            machine_firmware = Some(VmFirmware {
                code: resolved.code,
                vars,
                secure_boot: resolved.secure_boot,
            });
            tpm_socket = Some(socket);
        }

        let qemu_params = crate::qemu::QemuLaunchParams {
            cid: self.cid,
            image: self.image.to_owned(),
            config: self.config.to_owned(),
            vmid: self.id.to_owned(),
            is_init,
            mac_address: self.mac_address.to_owned(),
            cancel_token: cancel_token.clone(),
            expected_to_exit: self.qemu_should_exit.clone(),
            firmware: machine_firmware,
            tpm_socket,
        };

        let mut qemu_handle = tokio::spawn(launch_qemu(qemu_params));
        let pid = match read_pid(&self.id).await {
            Ok(pid) => pid,
            Err(e) => {
                // QEMU was spawned but never wrote its pid file, so it cannot be
                // signalled by pid. Wait a bounded time for the task to finish on its
                // own, then stop the TPM instead of leaving a half-started VM behind.
                if tokio::time::timeout(Duration::from_secs(10), &mut qemu_handle)
                    .await
                    .is_err()
                {
                    warn!(
                        "VM-{} did not exit after its pid file could not be read; it may still be running",
                        self.id
                    );
                }
                if let Some(mut swtpm) = self.swtpm.take() {
                    swtpm.stop().await;
                }
                return Err(e);
            }
        };
        self.pid = Some(pid);

        // Windows guests cannot use vsock: resolve the DHCP lease for this VM's MAC
        // before SSH, then connect with the deploy-time host key pinned. Discovery is
        // bounded by the same timeout as the connection attempt.
        let mut windows_endpoint: Option<(std::net::SocketAddr, String)> = None;
        if self.image.guest_os == GuestOs::Windows {
            // Discovery polls `virsh` for up to `ssh_timeout`, which on a first boot is
            // the 900s deployment budget. Race it against QEMU and cancellation so a VM
            // that died right after starting reports why, instead of waiting out the
            // whole budget and blaming the (absent) DHCP lease.
            let discovery_budget = match self.first_boot_deadline {
                Some(deadline) => remaining_budget(deadline).ok_or_else(|| {
                    spent_first_boot_budget("the DHCP lease appeared", ssh_timeout)
                })?,
                None => ssh_timeout,
            };
            let discovery = discover_windows_endpoint(
                self.mac_address.clone(),
                self.ssh_host_key.clone(),
                discovery_budget,
            );
            tokio::pin!(discovery);
            let discovered = tokio::select! {
                result = &mut discovery => result,
                result = &mut qemu_handle => {
                    cancel_token.cancel();
                    self.pid = None;
                    if let Some(mut swtpm) = self.swtpm.take() {
                        swtpm.stop().await;
                    }
                    return Err(match result {
                        Ok(Ok(())) => anyhow::anyhow!(
                            "QEMU exited before the Windows guest obtained a DHCP lease"
                        ),
                        Ok(Err(e)) => anyhow::anyhow!(
                            "QEMU failed before the Windows guest obtained a DHCP lease: {e}"
                        ),
                        Err(e) => anyhow::anyhow!(
                            "QEMU task error before the Windows guest obtained a DHCP lease: {e}"
                        ),
                    });
                }
                _ = cancel_token.cancelled() => {
                    self.pid = None;
                    if let Some(mut swtpm) = self.swtpm.take() {
                        swtpm.stop().await;
                    }
                    return Err(anyhow::anyhow!(
                        "VM-{} launch was cancelled before the guest obtained a DHCP lease",
                        self.id
                    ));
                }
            };
            match discovered {
                Ok(endpoint) => windows_endpoint = Some(endpoint),
                Err(e) => {
                    if let Some(pid) = self.pid.take() {
                        terminate_qemu(pid).await;
                    }
                    reap_launch_task(qemu_handle, Duration::from_secs(5)).await;
                    if let Some(mut swtpm) = self.swtpm.take() {
                        swtpm.stop().await;
                    }
                    return Err(e);
                }
            }
        }
        let windows_ip = windows_endpoint
            .as_ref()
            .map(|(addr, _)| addr.ip().to_string());

        let mut ssh_handle = match windows_endpoint {
            Some((addr, host_key)) => {
                info!("🔎 VM-{} connecting over tcp to {addr}", self.id);
                let connect_budget = match self.first_boot_deadline {
                    Some(deadline) => remaining_budget(deadline)
                        .ok_or_else(|| spent_first_boot_budget("`sshd` answered", ssh_timeout))?,
                    None => ssh_timeout,
                };
                tokio::spawn(connect_ssh_windows(
                    addr,
                    connect_budget,
                    self.keypair.to_owned(),
                    cancel_token.clone(),
                    host_key.clone(),
                    // The seed medium is only dropped once the deployment marker was seen,
                    // so its presence means the guest may still be installing our key.
                    self.deploy_seed.is_some(),
                ))
            }
            None => tokio::spawn(connect_ssh(
                self.cid,
                ssh_timeout,
                self.keypair.to_owned(),
                cancel_token.clone(),
                self.mac_address.to_owned(),
            )),
        };

        let ssh_result = tokio::select! {
            result = &mut ssh_handle => {
                // A panicked SSH task is a launch failure like any other: return it as an
                // error value so the branch below tears QEMU, swtpm and the pid down
                // instead of propagating and detaching them.
                match result {
                    Ok(inner) => inner,
                    Err(e) => Err(anyhow::anyhow!("SSH task panicked: {e}")),
                }
            }
            result = &mut qemu_handle => {
                // QEMU completed or errored, cancel SSH task. Clear the pid and stop swtpm
                // here: the machine is not running any more, and a leftover handle would
                // report a live VM and keep the TPM process around until drop.
                cancel_token.cancel();
                self.pid = None;
                // The join handle already resolved in this branch; awaiting it again
                // would panic on a completed task.
                if let Some(mut swtpm) = self.swtpm.take() {
                    swtpm.stop().await;
                }
                match result {
                    Ok(Ok(())) => bail!("QEMU exited unexpectedly"),
                    Ok(Err(e)) => bail!(e),
                    Err(e) => bail!("QEMU task error: {e}"),
                }
            }
        };

        match ssh_result {
            Ok(session) => {
                // SSH completed, QEMU continues running
                self.ssh = Some(session);
                if windows_ip.is_some() {
                    // The leased address came from the host, not from inside the guest.
                    self.ip = windows_ip;
                }
                // Windows guests confirm their first-boot deployment on the first
                // session and drop the seed medium afterwards; no-op for Linux.
                if let Err(e) = self.confirm_deployment().await {
                    // A guest that never confirms deployment cannot be used and still
                    // has the seed medium (client public key plus per-VM host private
                    // key) attached. Tear the VM down instead of returning an error
                    // while leaving QEMU, swtpm and the seed behind.
                    if let Some(ssh) = self.ssh.as_mut() {
                        let _ = ssh.close().await;
                    }
                    self.ssh = None;
                    self.ip = None;
                    if let Some(pid) = self.pid.take() {
                        terminate_qemu(pid).await;
                    }
                    let _ = qemu_handle.await;
                    if let Some(mut swtpm) = self.swtpm.take() {
                        swtpm.stop().await;
                    }
                    return Err(e);
                }
                Ok(())
            }
            Err(e) => {
                // SSH failed, QEMU should exit
                // Here we proactively terminate QEMU process to avoid leaving a zombie process, but we don't set the flag `qemu_should_exit` to true because the failure of SSH is unexpected.
                if let Some(pid) = self.pid.take() {
                    terminate_qemu(pid).await;
                }
                reap_launch_task(qemu_handle, Duration::from_secs(5)).await;
                if let Some(mut swtpm) = self.swtpm.take() {
                    swtpm.stop().await;
                }
                bail!(e)
            }
        }
    }
}

// Filesystem methods for Machine
//
// Every remote path goes through `GuestPath` so Windows drive paths keep guest
// semantics and invalid/unsupported forms are rejected before touching the guest.
impl Machine {
    /// Copies the contents of one file to another.
    ///
    /// On Linux guests this uses `cp -p --` inside the guest; on Windows guests it uses
    /// PowerShell `Copy-Item`, because `cp` does not exist there.
    pub async fn copy<P: AsRef<Path>, Q: AsRef<Path>>(&mut self, from: P, to: Q) -> Result<()> {
        let os = self.image.guest_os;
        let from = guest_path_from(os, from.as_ref())?;
        let to = guest_path_from(os, to.as_ref())?;
        let (ssh, cancel_token) = self.get_ssh("copy files")?;

        // Validate source and destination semantics to mirror std::fs::copy
        {
            let sftp = ssh.get_sftp().await?;
            let src_meta = sftp
                .metadata(from.as_str())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to stat source {}: {e}", from.as_str()))?;
            if src_meta.is_dir() {
                bail!("Source is a directory: {}", from.as_str());
            }

            if let Ok(dst_meta) = sftp.metadata(to.as_str()).await
                && dst_meta.is_dir()
            {
                bail!("Destination is a directory: {}", to.as_str());
            }
        }

        let cmd = match os {
            GuestOs::Linux => format!(
                "cp -p -- {} {}",
                escape(Cow::Borrowed(from.as_str())),
                escape(Cow::Borrowed(to.as_str()))
            ),
            GuestOs::Windows => windows::copy_file_command(from.as_str(), to.as_str()),
        };
        let (code, _stdout, stderr) = ssh.call_probe(&cmd, cancel_token).await?;
        if code != 0 {
            bail!(
                "Failed to copy file {} to {} (exit code {}): {}",
                from.as_str(),
                to.as_str(),
                code,
                String::from_utf8_lossy(&stderr)
            );
        }

        Ok(())
    }

    /// Creates a new, empty directory at the provided path.
    pub async fn create_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("create a directory")?;

        let sftp = ssh.get_sftp().await?;
        sftp.create_dir(path.as_str()).await?;

        Ok(())
    }

    /// Recursively create a directory and all of its parent components if they are missing.
    pub async fn create_dir_all<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("create a directory")?;

        ssh.create_dir_all(&path).await?;

        Ok(())
    }

    /// Returns `Ok(true)` if the path points at an existing entity.
    pub async fn exists<P: AsRef<Path>>(&mut self, path: P) -> Result<bool> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("check a path")?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.try_exists(path.as_str()).await?)
    }

    /// Creates a new hard link on the filesystem.
    ///
    /// Windows guests have no POSIX hard links over SFTP, so this is an explicit error
    /// rather than a silent no-op.
    pub async fn hard_link<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        original: P,
        link: Q,
    ) -> Result<()> {
        let os = self.image.guest_os;
        let original = guest_path_from(os, original.as_ref())?;
        let link = guest_path_from(os, link.as_ref())?;
        ensure_supported(os, PosixOnlyOperation::HardLink, &original)?;
        let (ssh, _) = self.get_ssh("create a hard link")?;

        let sftp = ssh.get_sftp().await?;
        sftp.hardlink(original.as_str(), link.as_str()).await?;

        Ok(())
    }

    /// Given a path, queries the file system to get information about a file, directory, etc.
    pub async fn metadata<P: AsRef<Path>>(&mut self, path: P) -> Result<Metadata> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("read metadata")?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.metadata(path.as_str()).await?)
    }

    /// Reads the entire contents of a file into a bytes vector.
    pub async fn read<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<u8>> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("read a file")?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.read(path.as_str()).await?)
    }

    /// Returns an iterator over the entries within a directory.
    pub async fn read_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<ReadDir> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("list a directory")?;

        let sftp = ssh.get_sftp().await?;
        Ok(sftp.read_dir(path.as_str()).await?)
    }

    /// Reads a symbolic link, returning the file that the link points to.
    ///
    /// Windows guests report this as unsupported instead of returning a misleading path.
    pub async fn read_link<P: AsRef<Path>>(&mut self, path: P) -> Result<PathBuf> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        ensure_supported(os, PosixOnlyOperation::ReadLink, &path)?;
        let (ssh, _) = self.get_ssh("read a symlink")?;

        let sftp = ssh.get_sftp().await?;
        Ok(PathBuf::from(sftp.read_link(path.as_str()).await?))
    }

    /// Reads the entire contents of a file into a string.
    pub async fn read_to_string<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("read a file")?;

        let sftp = ssh.get_sftp().await?;
        let bytes = sftp.read(path.as_str()).await?;
        Ok(String::from_utf8(bytes)?)
    }

    /// Removes a directory at provided path, after removing all its contents.
    pub async fn remove_dir_all<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        // Collect the tree first, then delete children before their parents.
        let (ssh, cancel_token) = self.get_ssh("remove a directory tree")?;
        let entries = ssh
            .walk_remote_dir(&path, /*follow_links=*/ false, cancel_token.clone())
            .await?;

        for entry in entries.iter().rev() {
            if cancel_token.is_cancelled() {
                bail!("remove_dir_all cancelled");
            }
            let (ssh, _) = self.get_ssh("remove a file")?;
            let sftp = ssh.get_sftp().await?;
            if entry.file_type().is_dir() {
                sftp.remove_dir(entry.path().as_str()).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to remove remote directory {}: {}",
                        entry.path().as_str(),
                        e
                    )
                })?;
            } else {
                sftp.remove_file(entry.path().as_str()).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to remove remote file {}: {}",
                        entry.path().as_str(),
                        e
                    )
                })?;
            }
        }

        Ok(())
    }

    /// Removes a file from the filesystem on VM.
    pub async fn remove_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let (ssh, _) = self.get_ssh("remove a file")?;

        let sftp = ssh.get_sftp().await?;
        sftp.remove_file(path.as_str()).await?;

        Ok(())
    }

    /// Renames a file or directory to a new name.
    pub async fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&mut self, from: P, to: Q) -> Result<()> {
        let os = self.image.guest_os;
        let from = guest_path_from(os, from.as_ref())?;
        let to = guest_path_from(os, to.as_ref())?;
        let (ssh, _) = self.get_ssh("rename a path")?;

        let sftp = ssh.get_sftp().await?;
        sftp.rename(from.as_str(), to.as_str()).await?;

        Ok(())
    }

    /// Changes the permissions found on a file or a directory.
    ///
    /// Windows guests use ACLs, not POSIX mode bits, so this is unsupported rather than a
    /// change that silently does nothing.
    pub async fn set_permissions<P: AsRef<Path>>(
        &mut self,
        path: P,
        perm: Permissions,
    ) -> Result<()> {
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        ensure_supported(os, PosixOnlyOperation::SetPermissions, &path)?;
        let (ssh, _) = self.get_ssh("set permissions")?;

        {
            let sftp = ssh.get_sftp().await?;
            let mut meta = sftp
                .metadata(path.as_str())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to stat {}: {}", path.as_str(), e))?;

            let mode = perm.mode();
            meta.permissions = Some(mode);

            sftp.set_metadata(path.as_str(), meta).await?;
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
        let os = self.image.guest_os;
        let path = guest_path_from(os, path.as_ref())?;
        let contents = contents.as_ref();
        let (ssh, _) = self.get_ssh("write a file")?;

        let sftp = ssh.get_sftp().await?;
        let _ = sftp.create(path.as_str()).await?;
        sftp.write(path.as_str(), contents).await?;

        Ok(())
    }
}

/// Whether a `/proc/<pid>/cmdline` payload belongs to QEMU.
///
/// Only Qlean's own QEMU process may be signalled. `/proc/<pid>` existing is not proof:
/// after a crash the kernel can hand the same pid to an unrelated process, and SIGKILLing
/// that would destroy somebody else's work.
fn cmdline_is_qemu(cmdline: &[u8]) -> bool {
    // Only argv[0] names the program: a later argument can mention QEMU without the
    // process being QEMU (`-D /tmp/qemu-system-x86_64.log`), so scanning the whole
    // command line would be a false positive.
    let program = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
    let program = String::from_utf8_lossy(program);
    let program = program.rsplit('/').next().unwrap_or_default();
    program.starts_with("qemu-system") || program.starts_with("qemu-kvm")
}

/// Whether `pid` still looks like the QEMU process Qlean started.
fn process_is_qemu(pid: u32) -> bool {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(cmdline) => cmdline_is_qemu(&cmdline),
        Err(_) => false,
    }
}

/// SIGKILL a pid only when it is still QEMU.
///
/// Returns whether the signal was delivered, so callers can report pid reuse or a refused
/// signal instead of leaving a misleading "killed" impression. A process that is already
/// gone counts as delivered: that is the state the caller wanted.
fn kill_if_qemu(pid: u32) -> bool {
    if !process_is_qemu(pid) {
        warn!(
            "not sending SIGKILL to pid {pid}: it no longer looks like the QEMU process Qlean started (the pid was probably reused)"
        );
        return false;
    }
    match signal_kill(pid) {
        Ok(()) => true,
        Err(error) => {
            warn!("failed to send SIGKILL to pid {pid}: {error}");
            false
        }
    }
}

/// Send SIGTERM through `kill(2)`, reporting a refusal instead of ignoring it.
fn signal_term(pid: u32) -> std::io::Result<()> {
    // SAFETY: `kill` with a positive pid only delivers a signal; it does not touch memory.
    let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if sent == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

/// Wait for a launch task to finish, but never forever.
///
/// The failure paths of `launch` must surface the original error: a QEMU that refuses to die
/// would otherwise leave this await hanging on its pipe readers and the user would see
/// nothing at all. Returns whether the task had to be aborted.
async fn reap_launch_task<T>(mut task: tokio::task::JoinHandle<T>, grace: Duration) -> bool {
    if tokio::time::timeout(grace, &mut task).await.is_ok() {
        return false;
    }
    warn!("QEMU did not exit within {grace:?} after the kill, abandoning the launch task");
    task.abort();
    true
}

/// SIGKILL `pid` through `kill(2)` rather than an external `kill` program.
fn signal_kill(pid: u32) -> std::io::Result<()> {
    // SAFETY: `kill` with a positive pid only delivers a signal; it does not touch memory.
    let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if sent == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

/// What a teardown poll should do next, given the QEMU process and the elapsed grace.
///
/// Pure so the three ways out of the wait loop are testable without a live QEMU:
/// `StillGone` (the usual case), `KeepWaiting` (guest is powering down), `ForceKill` (grace
/// expired, no signal sent yet) and `Unkillable` (SIGKILL was sent and the process is still
/// there, which must not be reported as a clean shutdown).
#[derive(Debug, PartialEq, Eq)]
enum TeardownStep {
    StillGone,
    KeepWaiting,
    ForceKill,
    Unkillable,
}

fn teardown_step(
    alive: bool,
    elapsed: std::time::Duration,
    grace: std::time::Duration,
    kill_sent: bool,
) -> TeardownStep {
    match (alive, elapsed > grace, kill_sent) {
        (false, ..) => TeardownStep::StillGone,
        (true, false, _) => TeardownStep::KeepWaiting,
        (true, true, false) => TeardownStep::ForceKill,
        (true, true, true) => TeardownStep::Unkillable,
    }
}

/// Convert a caller-supplied path into a validated guest path for `os`.
fn guest_path_from(os: GuestOs, path: &Path) -> Result<GuestPath> {
    let text = path.to_str().ok_or_else(|| {
        anyhow::anyhow!("guest path is not valid UTF-8 and cannot be sent over SFTP: {path:?}")
    })?;
    GuestPath::new(os, text)
}

/// Basename of a local path, as a UTF-8 name that can be joined onto a guest path.
fn local_basename(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("local path {path:?} has no usable basename"))
}

impl Drop for Machine {
    fn drop(&mut self) {
        // Ensure QEMU process is killed, but only if that pid is still QEMU: killing a
        // recycled pid would take down an unrelated process.
        if let Some(pid) = self.pid {
            kill_if_qemu(pid);
        }
        // Stop swtpm before the run dir disappears underneath its control socket; the
        // explicit take() makes the ordering deterministic instead of relying on field
        // drop order.
        if let Some(mut swtpm) = self.swtpm.take() {
            swtpm.stop_now();
        }
        // Clean up runtime files if configured to do so
        if self.config.clear {
            // `Drop` must never panic: a panic while unwinding aborts the process.
            match QleanDirs::new() {
                Ok(dirs) => {
                    let run_dir = dirs.runs.join(&self.id);
                    if let Err(error) = std::fs::remove_dir_all(&run_dir) {
                        debug!(
                            "failed to remove the run directory {}: {error}",
                            run_dir.display()
                        );
                    }
                }
                Err(error) => warn!(
                    "cannot remove the run directory of VM-{} on drop: {error}",
                    self.id
                ),
            }
        }
    }
}

/// What `is_running` can conclude from the host-side facts alone.
#[derive(Debug, PartialEq, Eq)]
enum RunningCheck {
    /// No QEMU pid was recorded, so nothing was launched.
    NotRunning,
    /// A pid exists but the QMP socket is gone: the domain exited and left a stale pid.
    NoControlSocket,
    /// Both exist, so only QMP can answer.
    AskQmp,
}

fn running_check(pid_present: bool, socket_present: bool) -> RunningCheck {
    match (pid_present, socket_present) {
        (false, _) => RunningCheck::NotRunning,
        (true, false) => RunningCheck::NoControlSocket,
        (true, true) => RunningCheck::AskQmp,
    }
}

/// Refuse to `spawn` a Windows guest whose deployment never ran.
///
/// `spawn` boots without the seed medium, so the guest never installs the SSH key and the
/// only symptom is a deployment wait that times out fifteen minutes later. The pool already
/// routed this case to `init`; the public entry point must not accept it either.
fn spawn_guard(needs_first_boot: bool, machine_id: &str) -> Result<()> {
    if !needs_first_boot {
        return Ok(());
    }
    bail!(
        "VM-{machine_id} has a Windows deployment that has not run yet, and `spawn` boots \
         without the deployment medium; use `init` for the first boot and `spawn` afterwards"
    )
}

/// Refuse to probe the deployment marker without a session.
///
/// A missing session is not evidence that the deployment has not finished: reporting
/// `Ok(false)` there made [`Machine::confirm_deployment`] poll for the whole budget and then
/// claim the deployment timed out. The distinction is the entire contract of
/// [`Machine::deploy_marker_present`], so it lives in one testable place.
fn marker_probe_guard(session_present: bool, machine_id: &str) -> Result<()> {
    if session_present {
        return Ok(());
    }
    Err(not_running_error(
        "check the Windows deployment marker",
        machine_id,
    ))
}

/// Why a session-scoped operation cannot run: the machine is not up.
///
/// Every `Machine` operation that talks to the guest goes through this one message, so a
/// machine that was never started, failed to start, or was already shut down reports the
/// same actionable reason instead of panicking on an `expect`.
fn not_running_error(operation: &str, machine_id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot {operation} on VM-{machine_id} because it is not running; start it first \
     (`init` for the first boot, `spawn` for a boot after that) and keep it running until \
     the operation finishes"
    )
}

/// Borrow the SSH session of a running machine, or explain why there is none.
///
/// Split out of [`Machine::get_ssh`] so the error path is testable without a guest: the
/// previous version used `expect`, which turned "not running" into a panic for every
/// caller (`upload`, `download`, the file helpers) while `exec` alone returned an error.
fn session_or_operation_error<'a>(
    ssh: &'a mut Option<Session>,
    cancel_token: Option<&CancellationToken>,
    operation: &str,
    machine_id: &str,
) -> Result<(&'a mut Session, CancellationToken)> {
    let Some(cancel_token) = cancel_token.cloned() else {
        return Err(not_running_error(operation, machine_id));
    };
    match ssh.as_mut() {
        Some(session) => Ok((session, cancel_token)),
        None => Err(not_running_error(operation, machine_id)),
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn a_shared_deadline_has_no_budget_once_it_passed() {
        let now = std::time::Instant::now();
        assert!(remaining_budget(now + Duration::from_secs(30)).is_some());
        assert!(
            remaining_budget(now).is_none(),
            "a deadline that is exactly now must not hand out a wait"
        );
        assert!(
            remaining_budget(now - Duration::from_secs(1)).is_none(),
            "a spent deadline must never turn into a wait again"
        );
    }

    #[test]
    fn a_spent_first_boot_budget_names_the_phase_and_the_whole_boot() {
        let error = spent_first_boot_budget("`sshd` answered", Duration::from_secs(900));
        let message = error.to_string();
        assert!(message.contains("`sshd` answered"), "{message}");
        assert!(
            message.contains("whole 900s deployment budget"),
            "{message}"
        );
        assert!(
            message.contains("not one phase"),
            "the message must say that later phases get no fresh wait: {message}"
        );
        assert!(message.contains("ssh_timeout"), "{message}");
    }

    fn config(ssh_timeout: Option<u64>) -> MachineConfig {
        MachineConfig {
            ssh_timeout,
            ..MachineConfig::default()
        }
    }

    #[test]
    fn run_dir_guard_removes_a_partially_built_run_directory() {
        let root = std::env::temp_dir().join(format!(
            "qlean-run-dir-guard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Mimic a construction that already wrote an overlay and a seed directory.
        std::fs::create_dir_all(root.join("seed")).unwrap();
        std::fs::write(root.join("overlay.img"), b"overlay").unwrap();

        drop(RunDirGuard::new(root.clone()));
        assert!(
            !root.exists(),
            "a failed construction must not leave the run directory behind"
        );
    }

    #[test]
    fn run_dir_guard_keeps_the_directory_after_a_successful_construction() {
        let root = std::env::temp_dir().join(format!(
            "qlean-run-dir-guard-keep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("overlay.img"), b"overlay").unwrap();

        RunDirGuard::new(root.clone()).disarm();
        assert!(
            root.join("overlay.img").is_file(),
            "disarmed guard must not clean up"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn reap_launch_task_returns_for_a_finished_task() {
        let task = tokio::spawn(async {});
        assert!(!reap_launch_task(task, std::time::Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn reap_launch_task_aborts_instead_of_hanging() {
        // A QEMU that refuses to die must not hide the original launch error.
        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        });
        let started = std::time::Instant::now();
        assert!(reap_launch_task(task, std::time::Duration::from_millis(50)).await);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the wait must be bounded"
        );
    }

    #[test]
    fn teardown_step_keeps_waiting_while_the_guest_shuts_down() {
        use std::time::Duration;
        let grace = Duration::from_secs(30);
        assert_eq!(
            teardown_step(true, Duration::from_secs(1), grace, false),
            TeardownStep::KeepWaiting
        );
        // Even after a kill was sent, a live process within the grace period is merely
        // taking its time.
        assert_eq!(
            teardown_step(true, Duration::from_secs(1), grace, true),
            TeardownStep::KeepWaiting
        );
        assert_eq!(
            teardown_step(false, Duration::from_secs(1), grace, false),
            TeardownStep::StillGone
        );
    }

    #[test]
    fn teardown_step_forces_a_kill_only_after_the_grace_period() {
        use std::time::Duration;
        let grace = Duration::from_secs(30);
        assert_eq!(
            teardown_step(true, grace, grace, false),
            TeardownStep::KeepWaiting
        );
        assert_eq!(
            teardown_step(true, grace + Duration::from_millis(1), grace, false),
            TeardownStep::ForceKill
        );
        // A process that disappeared during the grace period needs no signal at all.
        assert_eq!(
            teardown_step(false, grace + Duration::from_secs(1), grace, false),
            TeardownStep::StillGone
        );
    }

    #[test]
    fn teardown_step_reports_a_qemu_that_survived_the_kill() {
        use std::time::Duration;
        let grace = Duration::from_secs(30);
        assert_eq!(
            teardown_step(true, grace + Duration::from_secs(1), grace, true),
            TeardownStep::Unkillable
        );
    }

    #[test]
    fn cmdline_is_qemu_only_matches_qemu_programs() {
        // Real QEMU cmdlines are NUL-separated argv entries.
        assert!(cmdline_is_qemu(
            b"qemu-system-x86_64\0-machine\0q35,accel=kvm\0-drive\0file=overlay.img\0"
        ));
        assert!(cmdline_is_qemu(
            b"/usr/bin/qemu-system-aarch64\0-name\0vm\0"
        ));
        // The kernel's qemu-kvm symlink is QEMU as well.
        assert!(cmdline_is_qemu(b"/usr/bin/qemu-kvm\0-machine\0pc\0"));

        assert!(!cmdline_is_qemu(b""));
        assert!(!cmdline_is_qemu(b"/usr/bin/bash\0-c\0sleep 30\0"));
        // A later argument mentioning qemu must not make another program look like QEMU.
        assert!(!cmdline_is_qemu(
            b"/usr/bin/tee\0/tmp/qemu-system-x86_64.log\0"
        ));
        assert!(!cmdline_is_qemu(
            b"/usr/bin/qemu-img\0convert\0qemu-system-x86_64\0"
        ));
        assert!(!cmdline_is_qemu(b"/usr/bin/qemu-img\0create\0disk.qcow2\0"));
    }

    #[test]
    fn process_is_qemu_rejects_the_current_test_process() {
        // Guards the guard: the test binary is not QEMU, and the helper must say so, so a
        // recycled pid never gets SIGKILLed.
        assert!(!process_is_qemu(std::process::id()));
        assert!(!process_is_qemu(u32::MAX));
    }

    #[test]
    fn user_facing_messages_have_no_runs_of_spaces() {
        // A lost `\` continuation leaves a run of spaces in the middle of a sentence, which
        // reads like a formatting bug to the user. This is a regression guard for that.
        let messages = [
            spawn_guard(true, "abc123").unwrap_err().to_string(),
            not_running_error("upload files", "abc123").to_string(),
        ];
        for message in messages {
            for line in message.lines() {
                assert!(
                    !line.contains("  "),
                    "message line has a run of spaces: {line:?}"
                );
            }
        }
    }

    #[test]
    fn spawn_is_refused_while_the_windows_deployment_has_not_run() {
        // `spawn` boots without the seed medium, so the guest can never install the key; the
        // caller must be told now instead of after a 15-minute deployment timeout.
        let error = spawn_guard(true, "abc123")
            .expect_err("a pending deployment must be refused")
            .to_string();
        assert!(error.contains("VM-abc123"), "{error}");
        assert!(error.contains("init"), "{error}");
        assert!(spawn_guard(false, "abc123").is_ok());
    }

    #[test]
    fn running_check_only_asks_qmp_when_both_facts_are_present() {
        assert_eq!(running_check(false, false), RunningCheck::NotRunning);
        // A stale pid without a socket is still "not running".
        assert_eq!(running_check(false, true), RunningCheck::NotRunning);
        assert_eq!(running_check(true, false), RunningCheck::NoControlSocket);
        // Only here may a QMP failure be reported instead of "not running".
        assert_eq!(running_check(true, true), RunningCheck::AskQmp);
    }

    #[test]
    fn marker_probe_without_a_session_is_an_error_not_a_missing_marker() {
        // `Ok(false)` here would make a deployment wait the full budget and then blame the
        // guest for a host-side problem.
        let error = marker_probe_guard(false, "abc123")
            .expect_err("no session must be an error")
            .to_string();
        assert!(
            error.contains("check the Windows deployment marker"),
            "{error}"
        );
        assert!(error.contains("VM-abc123"), "{error}");
        assert!(marker_probe_guard(true, "abc123").is_ok());
    }

    #[test]
    fn not_running_error_names_the_machine_and_the_way_to_start_it() {
        let error = not_running_error("upload files", "abc123").to_string();
        assert!(
            error.contains("cannot upload files on VM-abc123"),
            "{error}"
        );
        assert!(error.contains("not running"), "{error}");
        assert!(
            error.contains("`init`") && error.contains("`spawn`"),
            "{error}"
        );
    }

    #[test]
    fn a_machine_without_a_session_reports_an_error_instead_of_panicking() {
        // The state after a failed `spawn` (token set, no session) and the state of a
        // machine that was never started must both come back as errors.
        let mut ssh: Option<Session> = None;
        let token = CancellationToken::new();
        for cancel_token in [Some(&token), None] {
            let error =
                match session_or_operation_error(&mut ssh, cancel_token, "run a command", "vm-1") {
                    Ok(_) => panic!("a machine without a session must not look like a running one"),
                    Err(error) => error.to_string(),
                };
            assert!(error.contains("cannot run a command on VM-vm-1"), "{error}");
            assert!(error.contains("not running"), "{error}");
        }
    }

    #[test]
    fn windows_first_boot_uses_the_deployment_budget() {
        // 900s, not the 180s/300s Linux connect budget: the guest still has to
        // install the seed key and enable sshd before it answers.
        assert_eq!(
            resolve_connect_timeout(&config(None), GuestOs::Windows, true),
            windows::deploy_timeout(&config(None))
        );
        assert_eq!(
            resolve_connect_timeout(&config(None), GuestOs::Windows, true),
            Duration::from_secs(windows::DEPLOY_TIMEOUT_SECS)
        );
    }

    #[test]
    fn windows_restart_keeps_the_connect_budget() {
        // No deployment happens on spawn, so the override is the plain connect budget.
        assert_eq!(
            resolve_connect_timeout(&config(Some(45)), GuestOs::Windows, false),
            Duration::from_secs(45)
        );
        assert_eq!(
            resolve_connect_timeout(&config(Some(45)), GuestOs::Windows, true),
            Duration::from_secs(45)
        );
    }

    #[test]
    fn linux_first_boot_keeps_the_connect_budget() {
        let conf = config(None);
        assert_eq!(
            resolve_connect_timeout(&conf, GuestOs::Linux, true),
            resolve_ssh_timeout(&conf)
        );
        assert_eq!(
            resolve_connect_timeout(&config(Some(45)), GuestOs::Linux, true),
            Duration::from_secs(45)
        );
    }
}
