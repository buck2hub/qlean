use std::{
    borrow::Cow,
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
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
        InteractiveShell, PersistedSshKeypair, Session, SftpRenameSink, abandon_staged_tree,
        connect_ssh, connect_ssh_windows, get_ssh_key, install_downloaded_tree, install_rename,
        staged_download_path,
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
    /// Whether to clear the runtime directory when the machine is dropped, defaults to `true`.
    ///
    /// The run directory holds the disk overlay, the OVMF vars image, the vTPM state and - on
    /// a Windows guest whose first boot has not finished - the seed medium, which carries the
    /// per-VM SSH *host* private key and the client public key. Setting this to `false` keeps
    /// all of it for diagnosis, and Qlean never removes it afterwards: nothing does, so
    /// removing it is the caller's job, and until then the deploy-time key material stays on
    /// disk (owner-only, but on disk).
    pub clear: bool,
    /// Launch timeout in seconds.
    ///
    /// Linux guests wait this long for SSH over vsock during launch; the default is `180`
    /// with KVM and `300` under TCG. A Windows guest has no vsock, so on its first boot
    /// this is the budget for the whole deployment (default `900`), and on later boots the
    /// plain budget for finding and connecting to the guest.
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

    /// Set the launch timeout in seconds (see [`MachineConfig::ssh_timeout`]).
    pub fn with_timeout(self, ssh_timeout: u64) -> Self {
        Self {
            ssh_timeout: Some(ssh_timeout),
            ..self
        }
    }

    /// Set whether to clear the runtime directory when the machine is dropped.
    ///
    /// `false` keeps the run directory - and with it the seed medium and its SSH host private
    /// key - after the machine is dropped, for diagnosis. It is not cleaned up later.
    pub fn with_clear(self, clear: bool) -> Self {
        Self { clear, ..self }
    }

    /// Reject field values that cannot describe a machine.
    ///
    /// Every field is public, so a caller can set a value QEMU has no interpretation for.
    /// Left alone, such a value surfaces much later and in the wrong place: `core = 0`
    /// becomes QEMU's own `-smp 0` error under "QEMU exited unexpectedly", and
    /// `ssh_timeout = 0` makes every phase of the launch report that the guest used up a
    /// budget it never had. The check runs before anything is written to disk, so a bad
    /// config leaves no run directory behind either.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.core > 0,
            "MachineConfig::core must be at least 1, got 0: a machine without a CPU cannot boot"
        );
        anyhow::ensure!(
            self.mem > 0,
            "MachineConfig::mem must be at least 1 (MB), got 0: a machine without memory cannot boot"
        );
        if let Some(disk) = self.disk {
            anyhow::ensure!(
                disk > 0,
                "MachineConfig::disk must be at least 1 (GB) when set, got 0: resizing the \
                 image to 0 GB would truncate it instead of enlarging it"
            );
        }
        if let Some(ssh_timeout) = self.ssh_timeout {
            anyhow::ensure!(
                ssh_timeout > 0,
                "MachineConfig::ssh_timeout must be at least 1 (second), got 0: a zero budget is \
                 already spent when the first attempt starts, so every launch reports that the \
                 guest never answered"
            );
        }
        Ok(())
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

/// Error for a Windows launch whose QEMU task finished before the guest reached a DHCP lease.
///
/// Kept in one place because two `select!` branches report it: the QEMU branch, and the
/// cancellation branch when the cancellation was caused by that QEMU exit. Both must say
/// the same thing, and it must name the QEMU outcome rather than the cancellation.
fn qemu_exit_before_lease(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow::anyhow!("QEMU exited before the Windows guest obtained a DHCP lease"),
        Ok(Err(e)) => {
            anyhow::anyhow!("QEMU failed before the Windows guest obtained a DHCP lease: {e}")
        }
        Err(e) => {
            anyhow::anyhow!("QEMU task error before the Windows guest obtained a DHCP lease: {e}")
        }
    }
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

/// Whether this launch runs under the single Windows first-boot deadline.
///
/// One deadline covers the lease wait, the `sshd` wait and the deploy-marker wait of the
/// *first* boot. A restart keeps the plain connect budget: the deployment happens once, and
/// a later boot that spent the deploy budget on a dead `sshd` would report a first-boot
/// timeout for a machine that had booted before.
///
/// The question is asked here, not spelled out inside `launch`, because a bare `is_init`
/// dropped from that expression kept the suite green (R244): the claim "later boots keep the
/// plain connect budget" had nothing watching it.
fn takes_first_boot_deadline(is_init: bool, guest_os: GuestOs) -> bool {
    is_init && guest_os == GuestOs::Windows
}

/// Whether this launch has to start the software TPM itself.
///
/// A machine that already started `swtpm` keeps that process: its state directory and control
/// socket are what the guest's TPM 2.0 device was created against. Replacing the handle with
/// a second `swtpm` on the same socket would drop the child that owns the first one, so the
/// restart's TPM would be attached to a socket the guest never saw (R244: `launch` decided
/// this with a bare `is_none()` and the suite could not tell).
fn needs_swtpm_start(swtpm_already_started: bool) -> bool {
    !swtpm_already_started
}

/// How long closing the SSH session may take during teardown.
///
/// Closing an SSH session is a write to the guest: `eof`/`close`/`disconnect` all wait for
/// the peer. A guest that has stopped answering (bugcheck, frozen kernel, network gone) can
/// therefore block teardown *before* it reaches the SIGKILL fallback, which would hang a test
/// instead of failing it.
const SSH_CLOSE_BUDGET: Duration = Duration::from_secs(5);

/// How long a local host tool on the launch path may take.
///
/// `qemu-img` creates only COW metadata and `xorriso` packs two small files, so both finish in
/// milliseconds on a healthy host. They read and write the run directory, though, and a run
/// directory on an unreachable mount (NFS, a hung FUSE mount) turns the call into an
/// unbounded wait *before* the first-boot budget even starts. The same budget the Windows seed
/// build uses keeps the launch path bounded end to end.
const LOCAL_TOOL_BUDGET: Duration = Duration::from_secs(120);

/// Await `future` for at most `budget`, returning `None` when the budget was spent.
///
/// Used by teardown paths where a stuck step must not prevent the next (stronger) step from
/// running: the caller reports the abandonment and then kills QEMU.
async fn bounded_teardown<F: std::future::Future>(
    budget: Duration,
    future: F,
) -> Option<F::Output> {
    tokio::time::timeout(budget, future).await.ok()
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

/// Budget left for `phase` inside a Windows first boot.
///
/// A first boot shares one deadline between the DHCP lease, `sshd` and the deployment
/// marker, so every phase has to ask for what is *left*. An expired deadline means the
/// documented budget is spent, and handing that phase a fresh timeout would quietly double
/// it: the guest could take the whole budget to answer SSH and then wait another whole
/// budget for the marker, which is exactly the "one boot, one budget" rule this code is
/// supposed to keep. `None` means this is not a first boot, so the plain budget applies.
fn remaining_first_boot_budget(
    deadline: Option<std::time::Instant>,
    budget: Duration,
    phase: &str,
) -> Result<Duration> {
    match deadline {
        Some(deadline) => {
            remaining_budget(deadline).ok_or_else(|| spent_first_boot_budget(phase, budget))
        }
        None => Ok(budget),
    }
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

/// Read the pid that `launch_qemu` recorded in `pid_file_path`.
///
/// The caller has to have cleared a pid file left by an earlier run first (see
/// [`clear_stale_pid_file`]), because this function returns the first parseable number it
/// finds: it cannot tell the pid of the QEMU that is starting now from the pid of the one that
/// died before it. The polling window exists because QEMU writes the file a moment after the
/// spawn returns.
async fn read_pid(pid_file_path: &Path) -> Result<u32> {
    // QEMU writes pid almost immediately after spawn; wait a short time to make cleanup reliable even on slower filesystems.
    for _ in 0..50 {
        if let Ok(pid_str) = tokio::fs::read_to_string(pid_file_path).await
            && let Ok(pid) = pid_str.trim().parse::<u32>()
        {
            return Ok(pid);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("Failed to read QEMU pid file at {:?}", pid_file_path);
}

/// Remove a pid file left behind by an earlier run of the same machine.
///
/// The run directory outlives a Qlean process that was killed, and it can be copied or
/// restored from a backup, so a `qemu.pid` naming a dead (or somebody else's) process can be
/// there *before* the next QEMU is started. [`read_pid`] accepts whatever parses, so without
/// this step the machine would record that old pid as its own: the identity check then sees a
/// process that is not this machine's QEMU, every signal step reports "nothing left to kill",
/// and the guest that is actually running keeps the overlay open.
///
/// A file that is already gone is success, and a file that cannot be removed is a failure:
/// starting QEMU on top of it would record the stale pid again.
async fn clear_stale_pid_file(pid_file_path: &Path) -> Result<()> {
    match tokio::fs::remove_file(pid_file_path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove the QEMU pid file left by an earlier run at {}; refusing to \
                 start QEMU because the pid it would record is the stale one",
                pid_file_path.display()
            )
        }),
    }
}

/// Whether this machine can still hold resources that need tearing down.
///
/// A QEMU pid or a live SSH session is proof that something started; the run directory alone
/// is not, because it exists from `Machine::new` onwards. The single implementation is shared
/// by `shutdown` (which refuses a machine that was never started) and by
/// `shutdown_if_started` (which uses it when the liveness probe could not answer).
fn started(pid_is_some: bool, ssh_is_some: bool) -> bool {
    pid_is_some || ssh_is_some
}

// Core methods for Machine
/// What an `opendir` answer says about the upload target.
///
/// `Ok` means the target is a directory and can be listed. A status the protocol defines as
/// "there is nothing here" - `NoSuchFile`, or the generic `Failure` a version-3 server sends
/// when it refuses to list a plain file - means it is not one. Every other outcome is *not an
/// answer*: a permission error, a dropped connection, a timeout or a packet the server should
/// not have sent say nothing about whether a directory is there, and the caller has to hear
/// about them instead of being told "not a directory".
fn directory_answer(outcome: Result<(), russh_sftp::client::error::Error>) -> Result<bool> {
    match outcome {
        Ok(()) => Ok(true),
        Err(russh_sftp::client::error::Error::Status(status))
            if matches!(
                status.status_code,
                russh_sftp::protocol::StatusCode::NoSuchFile
                    | russh_sftp::protocol::StatusCode::Failure
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

/// Whether the copy destination is a directory, or the reason nobody can say.
///
/// The question used to be `if let Ok(meta) = metadata(to) && meta.is_dir()`, which read every
/// failure as "not a directory": a permission error on the parent, an expired session and a
/// connection that went away all let the copy proceed towards a destination that may well have
/// been a directory. On a Windows guest that is the difference between replacing a file and
/// letting `Copy-Item` write *into* a directory. The two statuses that say "there is nothing
/// here" are decided in one place, by [`directory_answer`], so the upload, the download and the
/// copy can never disagree about what a definite no is.
fn destination_is_a_directory(
    meta: Result<russh_sftp::protocol::FileAttributes, russh_sftp::client::error::Error>,
) -> Result<bool> {
    match meta {
        Ok(attr) => Ok(attr.is_dir()),
        Err(error) => directory_answer(Err(error)).map(|_| false),
    }
}

/// The one sentence for a TPM that could not be confirmed gone.
///
/// Both teardown paths need it - the asynchronous one that stops the TPM before the run
/// directory is rebuilt, and the synchronous one in `Drop` - and two copies of a warning are
/// two chances for the second one to stop naming the directory nobody vouched for. R190 put the
/// fact in one place; this keeps it there while the drop path stops returning silently.
fn unconfirmed_swtpm_message(machine_id: &str, when: &str) -> String {
    format!(
        "VM-{machine_id}: swtpm did not confirm its exit {when}, so its TPM state directory is \
         not vouched for; check for a leftover swtpm process before reusing it"
    )
}

/// Whether the local download target is an existing directory, or the reason nobody can say.
///
/// The classification used to be `match metadata(..) { Ok(attr) if attr.is_dir() => .., _ => .. }`,
/// which answered "is this a directory" with "could I stat it": a permission error on the
/// parent, a symlink loop, a path whose component is a file (`ENOTDIR`) and a genuine I/O error
/// all read as "not a directory", so the download wrote to the path as given - and then failed
/// against a directory with a message about opening it, instead of saying that the host side
/// could not be inspected. Only the two answers the host filesystem defines as "there is no
/// directory here" count as a no.
fn host_target_is_a_directory(meta: std::io::Result<std::fs::Metadata>) -> std::io::Result<bool> {
    match meta {
        Ok(attr) => Ok(attr.is_dir()),
        // `NotFound`: the download creates the file, which is the same decision as before.
        // `NotADirectory`: a component of the path is a file, so the path itself cannot be a
        // directory - the answer is definite even though the call failed.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Whether the upload target is an existing directory, or the reason that cannot be told.
///
/// The question used to be answered by `read_dir(path).is_ok()`, which asks whether the path can
/// be *listed*. Those differ exactly where it matters: an unreadable directory, an expired
/// session or a server that answers `opendir` on a file with a generic status all came back as
/// "not a directory", and the local file was then aimed at the directory's own path instead of
/// inside it - on a Windows guest, `C:\out` where `C:\out\file.txt` was meant.
async fn remote_is_a_directory(ssh: &mut Session, path: &str) -> Result<bool> {
    let sftp = ssh.get_sftp().await?;
    let listed = sftp.read_dir(path).await.map(|_| ());
    directory_answer(listed).with_context(|| {
        format!("failed to find out whether the upload target {path} is a directory")
    })
}

impl Machine {
    /// Create a new Machine instance with specified image and configuration.
    pub async fn new(image: &Image, config: &MachineConfig) -> Result<Self> {
        // Before anything is written: a config QEMU cannot interpret must not leave a run
        // directory (or a half-created overlay) behind.
        config.validate()?;
        // A host that cannot run the guest must say so before it writes anything. This used to
        // run after the overlay was created, so a bare host failed on `qemu-img` (a program
        // that was not even part of the prerequisite list) and learned about OVMF, the TPM and
        // the seed builder one package at a time.
        if image.guest_os() == GuestOs::Windows {
            firmware::ensure_host_support()?;
        }
        // Prepare run directory
        let dirs = QleanDirs::new()?;
        let machine_id = nanoid!(12, &HEX_ALPHABET);
        let run_dir = Path::new(&dirs.runs).join(&machine_id);
        let seed_dir = run_dir.join("seed");
        // The run directory holds the per-VM host private key, the seed medium and the
        // disk overlay: it has to be owner-only from the moment it exists, not after a
        // `chmod` (the private key is written into it further down).
        crate::utils::create_owner_only_dir_all(&run_dir)?;
        crate::utils::create_owner_only_dir_all(&seed_dir)?;
        crate::utils::restrict_dir(&run_dir)?;
        // Everything below writes into `run_dir`; if it fails, the directory must not
        // outlive the failed construction.
        let run_dir_guard = RunDirGuard::new(run_dir.clone());

        // The disk this machine boots from, built once.
        //
        // `qemu-img` below writes this path, and `MachineImage::overlay` hands the same file
        // to `launch_qemu`, which turns it into the `-drive file=...` argument. R249: the path
        // used to be spelled twice, 17 lines apart - once as the argument `qemu-img` was told
        // to write, once as the field the machine carried - so a change to one left QEMU
        // opening a file `qemu-img` never created, reported by QEMU as
        // `Could not open '<path>': No such file or directory` on the first boot, after the
        // whole backing image had already been copied into the cache.
        let overlay_image = run_dir.join("overlay.img");

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
            .arg(&overlay_image);
        debug!(
            "Creating overlay image with command:\n{:?}",
            qemu_img_command.to_string()
        );
        let output = crate::utils::bounded_output(
            qemu_img_command,
            LOCAL_TOOL_BUDGET,
            "create the disk overlay from the cached image",
        )
        .await?;
        if !output.status.success() {
            bail!(
                "Failed to create overlay image: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Generate SSH keypair
        let ssh_keypair = get_ssh_key(&dirs.secrets)?;

        // Get a free CID
        let cid = get_free_cid(&dirs.runs, &run_dir)?;

        // Windows guests follow ADR-WIN-03: a pre-generalized image plus a per-VM
        // seed medium, instead of cloud-init NoCloud user-data.
        if image.guest_os() == GuestOs::Windows {
            // The host prerequisites were already checked at the top of this function, before
            // the run directory existed; nothing below can make them pass again.
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
        let output = crate::utils::bounded_output(
            xorriso_command,
            LOCAL_TOOL_BUDGET,
            "build the cloud-init seed ISO",
        )
        .await?;
        if !output.status.success() {
            bail!(
                "Failed to create seed ISO: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let machine_image = MachineImage {
            overlay: overlay_image,
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

    /// Initialize the machine (first boot: cloud-init on Linux, the per-VM deployment seed on Windows).
    ///
    /// A Windows guest may only be initialized once: its first boot consumes the seed
    /// medium, which is deleted once the deployment marker appears. A second `init`
    /// would boot without a seed (and without the host key the guest installed), so it
    /// is rejected here instead of failing later inside QEMU or at the host-key check.
    pub async fn init(&mut self) -> Result<()> {
        init_guard(
            start_actions(self.image.guest_os, self.deploy_seed.is_some()),
            &self.id,
        )?;
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
            let output = crate::utils::bounded_output(
                qemu_img_command,
                LOCAL_TOOL_BUDGET,
                "resize the disk overlay",
            )
            .await?;
            if !output.status.success() {
                bail!(
                    "Failed to resize image: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Same rule as `spawn`: a leftover token from a failed launch must not block a retry.
        if self.already_started() {
            bail!("Machine already initialized");
        }
        self.ssh_cancel_token = Some(CancellationToken::new());

        if let Err(err) = self.launch(true).await {
            self.abandon_launch();
            return Err(err);
        }

        Ok(())
    }

    /// What this machine's two pool entry points should do.
    ///
    /// The table itself is [`start_actions`]; this method is the only place that hands it this
    /// machine's two inputs. Asking it twice (once per pool question) would let the two
    /// questions be answered from different inputs - a Windows guest whose seed has just been
    /// consumed would answer "spawn" to one and "init" to the other - and swapping the
    /// columns is a one-token edit nothing would notice.
    fn routing(&self) -> StartActions {
        start_actions(self.image.guest_os, self.deploy_seed.is_some())
    }

    /// Whether starting this machine should run `init` rather than `spawn`.
    pub(crate) fn wants_init(&self) -> bool {
        self.routing().init_all == Start::Init
    }

    /// Whether this machine has a Windows deployment that has not run yet.
    ///
    /// Starting such a machine with `spawn` would boot a guest whose `sshd` has no
    /// installed key, so the deployment has to run first.
    pub(crate) fn needs_first_boot(&self) -> bool {
        self.routing().spawn_all == Start::Init
    }

    /// Spawn the machine (normal boot).
    pub async fn spawn(&mut self) -> Result<()> {
        info!("🔥 Spawning VM-{}", self.id);

        // Only a machine that is actually up counts as spawned: a failed launch leaves
        // the token behind, and refusing to retry would make the error unrecoverable.
        if self.already_started() {
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

    /// Whether this machine already holds a launch that the caller started.
    ///
    /// The cancel token marks "a launch was begun"; it stays behind when that launch fails, so
    /// on its own it is not proof of a running machine. A pid or a live session is. The two
    /// callers (`init` and `spawn`) have to answer this the same way, otherwise one of them
    /// refuses a retry after a failed start while the other allows it.
    fn already_started(&self) -> bool {
        self.ssh_cancel_token.is_some() && (self.pid.is_some() || self.ssh.is_some())
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

    /// Stop this machine's TPM process, and say so when it does not confirm its exit.
    ///
    /// Six teardown paths take the swtpm out of `self` - three pool-facing ones and three
    /// launch-failure ones. Each used to ignore what the stop returned, so a TPM that never
    /// confirmed its exit was dropped silently while the next start went on to rebuild the
    /// state directory it may still own.
    async fn stop_swtpm(&mut self) {
        let Some(mut swtpm) = self.swtpm.take() else {
            return;
        };
        if !swtpm.stop().await {
            warn!(
                "{}",
                unconfirmed_swtpm_message(&self.id, "while it was being stopped")
            );
        }
    }

    /// Tear down a launch that failed after QEMU was started.
    ///
    /// The three ways out of a launch that already has a live QEMU - the leased address was
    /// never discovered, the guest never confirmed its deployment, the SSH session failed -
    /// have to leave the same facts behind: no session, no pid, no TPM, and no launch task
    /// still being awaited. Written once, because a branch that forgets one of the four steps
    /// leaves a VM that `is_running` reports and a TPM that outlives it.
    ///
    /// The wait for QEMU to exit is bounded and abandons the task: a wedged QEMU must not
    /// hide the original launch error behind a hang (F176).
    async fn tear_down_failed_launch<T>(&mut self, qemu_handle: tokio::task::JoinHandle<T>) {
        if let Some(ssh) = self.ssh.as_mut() {
            let _ = ssh.close().await;
        }
        self.ssh = None;
        self.ip = None;
        if let Some(pid) = self.pid.take() {
            let identity = qmp::qmp_socket_path(&self.id).ok();
            terminate_qemu(pid, identity.as_deref()).await;
        }
        reap_launch_task(qemu_handle, Duration::from_secs(5)).await;
        self.stop_swtpm().await;
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

    /// A machine that was constructed but never started: no QEMU pid, no SSH session.
    ///
    /// This is the state a pool sees after a launch whose QMP socket never came up, and it is
    /// one of the states in which `is_running` fails instead of answering.
    #[cfg(test)]
    pub(crate) fn never_started_for_tests() -> Self {
        Self::for_tests_with_pid(None)
    }

    /// A machine fixture that claims `pid` as its QEMU process.
    ///
    /// Used by the teardown tests that hand it a real, live QEMU pid.
    #[cfg(test)]
    pub(crate) fn for_tests_with_pid(pid: Option<u32>) -> Self {
        Machine {
            id: "never-started".to_string(),
            image: MachineImage {
                overlay: PathBuf::from("/nonexistent/overlay.qcow2"),
                arch: GuestArch::Amd64,
                guest_os: GuestOs::Linux,
                seed: PathBuf::from("/nonexistent/seed.iso"),
            },
            config: MachineConfig::default(),
            keypair: PersistedSshKeypair {
                pubkey_str: String::new(),
                _pubkey_path: PathBuf::from("/nonexistent/id_ed25519.pub"),
                privkey_str: String::new(),
                privkey_path: PathBuf::from("/nonexistent/id_ed25519"),
            },
            ssh: None,
            cid: 3,
            pid,
            qemu_should_exit: Arc::new(AtomicBool::new(false)),
            ssh_cancel_token: None,
            mac_address: "52:54:00:00:00:01".to_string(),
            ip: None,
            swtpm: None,
            deploy_seed: None,
            ssh_host_key: None,
            first_boot_deadline: None,
        }
    }

    /// Shut down a machine whose liveness could not be probed.
    ///
    /// [`Machine::is_running`] answers "did a QMP session reply", and a hung or unreadable
    /// socket makes it fail even while QEMU is still running. Callers that would otherwise
    /// skip the shutdown (see `MachinePool::shutdown_all`) use this instead: a machine that
    /// never started has nothing to shut down, and one that did is asked to power down with
    /// the same budget and escalation as [`Machine::shutdown`].
    pub(crate) async fn shutdown_if_started(&mut self) -> Result<()> {
        if !started(self.pid.is_some(), self.ssh.is_some()) {
            return Ok(());
        }
        self.shutdown().await
    }

    /// Shutdown the machine.
    pub async fn shutdown(&mut self) -> Result<()> {
        if !started(self.pid.is_some(), self.ssh.is_some()) {
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

        if let Some(mut ssh) = self.ssh.take()
            && bounded_teardown(SSH_CLOSE_BUDGET, ssh.close())
                .await
                .is_none()
        {
            warn!(
                "closing the SSH session for VM-{} did not finish within {}s; the guest stopped \
                 answering, so teardown continues by killing QEMU",
                self.id,
                SSH_CLOSE_BUDGET.as_secs()
            );
        }

        if let Some(pid) = self.pid {
            debug!("Waiting for QEMU process {} to exit", pid);
            let identity = qmp::qmp_socket_path(&self.id).ok();
            let identity = identity.as_deref();
            let max_wait_time = Duration::from_secs(30);
            let poll_interval = Duration::from_millis(100);
            let start = std::time::Instant::now();
            let mut kill_sent = false;

            loop {
                // Leave `self.pid` set on error: a check that could not look says nothing
                // about the process, and reporting a clean shutdown here would let the next
                // start rebuild the overlay of a live guest.
                let alive = teardown_liveness(process_is_gone(pid), pid)?;
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
                        match kill_step(&force_kill(pid, identity)) {
                            KillStep::KeepPolling => {
                                kill_sent = true;
                                tokio::time::sleep(poll_interval).await;
                            }
                            KillStep::NothingLeft => {
                                // The pid no longer belongs to our QEMU, so there is nothing
                                // left for teardown to wait for.
                                break;
                            }
                            KillStep::NotShutDown(reason) => {
                                // The process is still our QEMU and still alive. Leave
                                // `self.pid` set: reporting a clean shutdown here would let
                                // the next start rebuild the overlay of a live guest.
                                bail!("{}", kill_not_shut_down_message(pid, &reason));
                            }
                        }
                    }
                    TeardownStep::Unkillable => {
                        // Leave `self.pid` set: the process is still running, so reporting a
                        // clean shutdown would let the next start rebuild the overlay of a
                        // live guest.
                        bail!("{}", unkillable_message(pid));
                    }
                }
            }
        }

        self.stop_swtpm().await;

        // The record of this run's QEMU pid is written and read through one function; a
        // removal that spelled the path itself would quietly stop matching the file the
        // launch reads as soon as either spelling moved.
        if let Ok(pid_file_path) = crate::qemu::pid_file_of(&self.id) {
            let _ = tokio::fs::remove_file(pid_file_path).await;
        }
        self.ssh = None;
        self.pid = None;
        self.ssh_cancel_token = None;
        self.ip = None;

        Ok(())
    }

    /// Upload file or directory to the machine.
    ///
    /// Remote paths are always built as `GuestPath` values, so a Windows drive path is never
    /// reinterpreted as a host path. A symbolic link - the local path itself or an entry
    /// inside a tree - is never followed: a Windows guest rejects it by name, while a Linux
    /// guest gets the link recreated.
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

        // Classify the local path itself, not what it points at. `metadata` follows a link, so
        // a link handed to `upload` used to pass for the file it points at: its target's bytes
        // were uploaded and, on a Windows guest, the rule below never ran.
        let meta = tokio::fs::symlink_metadata(local_path).await?;
        let is_link = meta.file_type().is_symlink();
        if meta.is_file() || is_link {
            // Decide final remote target path (dir vs file path)
            let remote_target = {
                let is_dir = remote_is_a_directory(ssh, remote_path.as_str()).await?;
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

            if is_link {
                upload_symbolic_link(ssh, os, local_path, &remote_target).await?;
                return Ok(());
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
                let remote_entry = remote_root.join(guest_relative_path(rel)?)?;

                if ty.is_dir() {
                    ssh.create_dir_all(&remote_entry).await?;
                } else if ty.is_file() {
                    if let Some(parent) = remote_entry.parent() {
                        ssh.create_dir_all(&parent).await?;
                    }
                    ssh.upload_file(entry.path(), &remote_entry, cancel_token.clone())
                        .await?;
                } else if ty.is_symlink() {
                    upload_symbolic_link(ssh, os, entry.path(), &remote_entry).await?;
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

        // Classify the path itself, not what it points at: `stat` follows a link, so a
        // symlink to a regular file would pass for a file and `download_file` would copy the
        // target's bytes as if the link had been the thing asked for. The walk reports a
        // link as a link, and so does this first step.
        let remote_meta = {
            let sftp = ssh.get_sftp().await?;
            sftp.symlink_metadata(remote_path.as_str())
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to stat remote path {}: {}", remote_path.as_str(), e)
                })?
        };
        if remote_meta.file_type().is_symlink() {
            bail!(
                "cannot download the symbolic link {} as a link; download its target instead",
                remote_path.as_str()
            );
        }

        if !remote_meta.is_dir() {
            // Decide final local target path (dir vs file path)
            let local_target = if host_target_is_a_directory(tokio::fs::metadata(local_path).await)
                .with_context(|| {
                    format!(
                        "failed to find out whether the download target {local_path:?} is a \
                         directory"
                    )
                })? {
                let name = remote_path.file_name().ok_or_else(|| {
                    anyhow::anyhow!(
                        "remote path {} has no basename to reuse",
                        remote_path.as_str()
                    )
                })?;
                local_path.join(name)
            } else {
                local_path.to_path_buf()
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
            // For directory: mirror into local_path/<basename>, but let that name mean what it
            // says. The walk fills a hidden sibling and the tree takes the name only after the
            // last entry arrived - a directory that exists but holds half an answer is worse than
            // no directory, because it reads as the answer.
            let base = remote_path.file_name().ok_or_else(|| {
                anyhow::anyhow!(
                    "remote path {} has no basename to reuse",
                    remote_path.as_str()
                )
            })?;
            let local_root = local_path.join(base);
            let staged_root = staged_download_path(&local_root);
            if let Some(parent) = staged_root.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    anyhow::anyhow!("Failed to create local directory {:?}: {}", parent, e)
                })?;
            }
            tokio::fs::create_dir_all(&staged_root).await.map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create the staged download {:?}: {}",
                    staged_root,
                    e
                )
            })?;

            // Use walk_remote_dir for DFS traversal
            let outcome: Result<()> = async {
                let entries = ssh
                    .walk_remote_dir(&remote_path, cancel_token.clone())
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
                    let staged_entry = if rel.is_empty() {
                        staged_root.clone()
                    } else {
                        staged_root.join(rel)
                    };

                    if e.file_type().is_dir() {
                        tokio::fs::create_dir_all(&staged_entry).await.map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to create local directory {:?}: {}",
                                staged_entry,
                                e
                            )
                        })?;
                    } else if e.file_type().is_file() {
                        if let Some(parent) = staged_entry.parent() {
                            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                                anyhow::anyhow!(
                                    "Failed to create local directory {:?}: {}",
                                    parent,
                                    e
                                )
                            })?;
                        }
                        ssh.download_file(e.path(), &staged_entry, cancel_token.clone())
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

                Ok(())
            }
            .await;

            match outcome {
                Ok(()) => install_downloaded_tree(&staged_root, &local_root)?,
                Err(error) => return Err(abandon_staged_tree(&staged_root, error)),
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
        // waits, so the documented budget bounds the whole boot instead of one phase. An
        // expired deadline is a failure here, not a fresh budget.
        let remaining = remaining_first_boot_budget(
            self.first_boot_deadline,
            timeout,
            "the deployment marker appeared",
        )?;
        // A marker poll that cannot reach the guest says nothing about deployment: the
        // session may have died because the guest rebooted. Retrying that for the whole
        // budget would report "deployment did not finish" 15 minutes later, so give up
        // after a few consecutive transport failures with an actionable message.
        let mut watch = MarkerWatch::default();
        loop {
            let poll = self.deploy_marker_present().await;
            match marker_poll_outcome(&poll) {
                MarkerPoll::Deployed => break,
                MarkerPoll::NotYet | MarkerPoll::TransportError => {}
            }
            if watch.observe(marker_poll_outcome(&poll)) {
                let error = poll.expect_err("only a transport error can end the wait");
                return Err(error).with_context(|| {
                    format!(
                        "lost the SSH session to VM-{} while waiting for the Windows \
                         deployment marker; the guest probably rebooted or stopped sshd. \
                         Retry with `spawn` once the guest is reachable again",
                        self.id
                    )
                });
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
        let cmd = windows::marker_probe_command();
        let (code, stdout, stderr) = ssh.call_probe(&cmd, cancel_token).await?;
        if code != 0 {
            bail!(
                "deployment marker probe `{cmd}` exited with {code}: {}",
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&stdout).contains(windows::MARKER_PRESENT_TOKEN))
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
            .call_probe(&windows::guest_ip_query_command(), cancel_token)
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
    /// `false` means this run directory is free: no live QEMU answers for it. A guest that
    /// stopped is not a machine that left — a paused guest, a guest stopped by `io-error` on a
    /// full host disk, an `internal-error` or a panic all still have a QEMU process that owns
    /// the overlay, so the liveness check reads the QMP run state and not the guest CPU flag.
    ///
    /// A failed QMP query is reported instead of being folded into `false`: the callers use
    /// `false` to decide that a launch is safe, and starting a second QEMU on a live domain's
    /// disk would corrupt it. A missing socket is proof that the domain is gone only when the
    /// process is gone too; a live QEMU without its socket is a missing socket, not a dead
    /// domain, and is reported as such. A process table that cannot be read is reported for
    /// the same reason: a host with `hidepid=2` answers "no such process" for every pid, and
    /// that answer is what tells a launch the overlay is free.
    pub async fn is_running(&self) -> Result<bool> {
        let socket_path = qmp::qmp_socket_path(&self.id)?;
        let qemu_alive = match self.pid {
            None => false,
            // A pid that answers with somebody else's QMP socket is somebody else's QEMU: the
            // domain this machine recorded is gone, whatever the pid is running now. A pid
            // whose state or command line cannot be read answers neither question, so it is
            // reported instead of being counted as a dead domain: `false` here is what lets a
            // launch start a second QEMU on the live one's overlay.
            Some(pid) => process_is_gone(pid)
                .and_then(|gone| {
                    if gone {
                        Ok(false)
                    } else {
                        process_is_this_machines_qemu(pid, Some(socket_path.as_path()))
                    }
                })
                .map_err(|error| {
                    anyhow::anyhow!("{}", unconfirmed_liveness_message(pid, &error))
                })?,
        };
        match running_check(self.pid.is_some(), socket_path.exists(), qemu_alive) {
            RunningCheck::NotRunning => Ok(false),
            RunningCheck::NoControlSocket => Ok(false),
            RunningCheck::LiveWithoutSocket => bail!(
                "VM-{} still has a live QEMU process ({}) but its control socket at {} is \
                 missing; the socket is gone, not the domain. Check the process before \
                 starting it again, or a second QEMU will fight it for the disk",
                self.id,
                self.pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "unknown pid".to_owned()),
                socket_path.display()
            ),
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
        self.first_boot_deadline = takes_first_boot_deadline(is_init, self.image.guest_os)
            .then(|| std::time::Instant::now() + ssh_timeout);

        // The pid file is cleared *before* the spawn: `read_pid` accepts the first number that
        // parses, so a file left by an earlier run of this machine would be read back as the
        // pid of the QEMU starting now (see `clear_stale_pid_file`).
        let pid_file = crate::qemu::pid_file_of(&self.id)?;
        clear_stale_pid_file(&pid_file).await?;

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
            // The run directory holds the TPM state and the per-VM host key, so it is created
            // owner-only even here, where `init` normally made it already: `create_dir_all`
            // would give it the umask's permissions for as long as a `chmod` had not run.
            crate::utils::create_owner_only_dir_all(&run_dir)?;
            let resolved = firmware::resolve_ovmf()?;
            let vars = firmware::prepare_vars(&run_dir, &resolved)?;
            if needs_swtpm_start(self.swtpm.is_some()) {
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
        let pid = match read_pid(&pid_file).await {
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
                self.stop_swtpm().await;
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
            let discovery_budget = remaining_first_boot_budget(
                self.first_boot_deadline,
                ssh_timeout,
                "the DHCP lease appeared",
            )?;
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
                    self.stop_swtpm().await;
                    return Err(qemu_exit_before_lease(result));
                }
                _ = cancel_token.cancelled() => {
                    self.pid = None;
                    self.stop_swtpm().await;
                    // `launch_qemu` cancels this very token as part of reporting its own
                    // exit, so the cancellation can be the *consequence* of the launch
                    // failing. `select!` polls ready branches in random order, which used
                    // to surface "launch was cancelled" (naming the symptom) for a guest
                    // that simply never started (the cause). A finished task is the
                    // earlier event; report it.
                    if qemu_handle.is_finished() {
                        return Err(qemu_exit_before_lease(qemu_handle.await));
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
                    self.tear_down_failed_launch(qemu_handle).await;
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
                let connect_budget = remaining_first_boot_budget(
                    self.first_boot_deadline,
                    ssh_timeout,
                    "`sshd` answered",
                )?;
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
                self.stop_swtpm().await;
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
                    self.tear_down_failed_launch(qemu_handle).await;
                    return Err(e);
                }
                Ok(())
            }
            Err(e) => {
                // SSH failed, QEMU should exit. Kill it here rather than waiting for the
                // guest to notice: the failure of SSH is unexpected, and a zombie QEMU would
                // keep reporting itself as a running machine.
                self.tear_down_failed_launch(qemu_handle).await;
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

            if destination_is_a_directory(sftp.metadata(to.as_str()).await).with_context(|| {
                format!(
                    "failed to find out whether the copy destination {} is a directory",
                    to.as_str()
                )
            })? {
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
        let entries = ssh.walk_remote_dir(&path, cancel_token.clone()).await?;

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
    ///
    /// The destination has to be free: this does not replace an existing file, and an occupied
    /// destination is refused before anything is sent (remove it first if it is meant to be
    /// replaced). The decision is Qlean's, not the guest's, because the two guests do not answer
    /// the same question the same way - SFTP's standard rename is defined to fail when the new
    /// name exists, while OpenSSH's `sftp-server` performs the system's `rename(2)`, which
    /// replaces it. `std::fs::rename`, which the rest of this type mirrors, replaces as well, so
    /// leaving the outcome to the server would make the same call replace on one guest and fail
    /// on another with nothing in the signature to tell them apart.
    pub async fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&mut self, from: P, to: Q) -> Result<()> {
        let os = self.image.guest_os;
        let from = guest_path_from(os, from.as_ref())?;
        let to = guest_path_from(os, to.as_ref())?;
        let (ssh, _) = self.get_ssh("rename a path")?;

        let sftp = ssh.get_sftp().await?;
        let mut sink = SftpRenameSink(sftp);
        install_rename(&mut sink, from.as_str(), to.as_str()).await
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

        // Staged on the guest, like an upload: opening the target with `TRUNCATE` first would
        // leave a half-written file wearing the caller's name if the write failed or the session
        // dropped, and on a Windows guest an open handle denies the rename that installs it.
        ssh.write_file(contents, &path).await
    }
}

/// Whether a `/proc/<pid>/cmdline` payload belongs to *this* machine's QEMU.
///
/// Only Qlean's own QEMU process may be signalled. `/proc/<pid>` existing is not proof:
/// after a crash the kernel can hand the same pid to an unrelated process, and SIGKILLing
/// that would destroy somebody else's work.
///
/// Naming QEMU is not proof either. Every other QEMU on the host - the user's own VM,
/// another checkout's guest - names itself `qemu-system-*`, so `argv[0]` alone let a
/// recycled pid that is running somebody else's VM through the check, which is the one case
/// the check exists for. The command line must also carry this machine's own QMP socket:
/// that is the address the process is supposed to serve, it is how `is_running` and teardown
/// find the domain, and Qlean always passes it as `-chardev socket,...,path=<socket>`.
///
/// `socket_path` is `None` when the caller cannot compute it (a `Drop` that runs while the
/// directories are unavailable). Then only the `argv[0]` rule applies, which is what every
/// caller had before, so an unavailable identity cannot leave a QEMU running.
pub(crate) fn cmdline_is_this_machines_qemu(cmdline: &[u8], socket_path: Option<&Path>) -> bool {
    // Only argv[0] names the program: a later argument can mention QEMU without the
    // process being QEMU (`-D /tmp/qemu-system-x86_64.log`), so scanning the whole
    // command line would be a false positive.
    let mut arguments = cmdline.split(|byte| *byte == 0);
    let program = arguments.next().unwrap_or_default();
    let program = String::from_utf8_lossy(program);
    let program = program.rsplit('/').next().unwrap_or_default();
    if !(program.starts_with("qemu-system") || program.starts_with("qemu-kvm")) {
        return false;
    }
    let Some(socket_path) = socket_path else {
        return true;
    };
    let socket = socket_path.to_string_lossy();
    arguments.any(|argument| String::from_utf8_lossy(argument).contains(socket.as_ref()))
}

/// Process state letter from `/proc/<pid>/stat`, if the process still exists.
///
/// `/proc/<pid>` keeps existing for a **zombie**, so "the directory is there" is not
/// evidence that anything is still running. A killed QEMU that nobody reaped (its launch
/// task was aborted, or teardown ran from a different code path) therefore looked alive for
/// the whole 30s teardown budget and produced a misleading "force killing" message.
/// State letter from an injected process table, so both answers are testable.
///
/// `Ok(None)` means "this process table has no entry for that pid"; a process table that
/// cannot be read is an `Err`. Folding the second into the first is how a hidden `/proc`
/// (`hidepid=2`, a chroot, a sandbox) answered every question about every process with "that
/// one is gone": teardown reported a clean shutdown of a live guest and cleared the pid, and
/// `is_running` answered "not running" for a domain whose overlay a second launch then reused.
fn state_in(proc_root: &Path, pid: u32) -> std::io::Result<Option<char>> {
    let stat = match std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(process_state_of(&stat))
}

/// State letter of a `/proc/<pid>/stat` line (split out so it is testable without a pid).
fn process_state_of(stat: &str) -> Option<char> {
    // Field 2 is the command name in parentheses and may itself contain parentheses, so the
    // state letter is the first non-space character after the last `)`.
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().next()?.chars().next()
}

/// Whether `pid` is gone for teardown purposes.
///
/// Exited-but-unreaped (`Z`, and the transient `X`) counts as gone: such a process cannot be
/// signalled back to life, and waiting for its `/proc` entry to disappear waits for a reaper
/// that may never come.
fn process_is_gone(pid: u32) -> std::io::Result<bool> {
    process_is_gone_in(Path::new("/proc"), pid)
}

/// `process_is_gone` against an injected process table (see [`state_in`] for why `Err`).
fn process_is_gone_in(proc_root: &Path, pid: u32) -> std::io::Result<bool> {
    Ok(match state_in(proc_root, pid)? {
        None => true,
        Some(state) => matches!(state, 'Z' | 'X' | 'x'),
    })
}

/// Whether `pid` still looks like the QEMU process Qlean started for this machine.
fn process_is_this_machines_qemu(pid: u32, socket_path: Option<&Path>) -> std::io::Result<bool> {
    identity_in(Path::new("/proc"), pid, socket_path)
}

/// `process_is_this_machines_qemu` against an injected process table.
///
/// A pid that left the table between two reads is "not ours" (`Ok(false)`, the pid is free);
/// a command line that exists but cannot be read (`EACCES` under `hidepid`, a sandbox) is an
/// `Err`, because "not ours" is the answer that licenses a launch to reuse the overlay and
/// teardown to stop waiting.
fn identity_in(proc_root: &Path, pid: u32, socket_path: Option<&Path>) -> std::io::Result<bool> {
    match std::fs::read(proc_root.join(pid.to_string()).join("cmdline")) {
        Ok(cmdline) => Ok(cmdline_is_this_machines_qemu(&cmdline, socket_path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// What one SIGKILL attempt achieved.
///
/// A single `bool` used to carry this and conflated two very different worlds: "the pid is
/// no longer our QEMU" (nothing left to wait for) and "SIGKILL was refused" (our QEMU is
/// still alive). Treating the second like the first made `shutdown` report a clean stop while
/// a live guest still held its disk.
#[derive(Debug, PartialEq, Eq)]
enum KillOutcome {
    /// The pid no longer belongs to Qlean's QEMU: it exited, or the pid was reused.
    Gone,
    /// SIGKILL was delivered; the process still has to leave `/proc`.
    Killed,
    /// The pid is still our QEMU and the signal was refused, so it is alive and ours.
    Refused(String),
    /// The pid could not be identified as our QEMU, so it was not signalled and its absence
    /// cannot be claimed either. Treating this like `Gone` would report a clean shutdown of a
    /// machine whose QEMU still holds the overlay.
    Unconfirmed(String),
}

/// What teardown should do after one SIGKILL attempt.
#[derive(Debug, PartialEq, Eq)]
enum KillStep {
    /// The signal landed; keep polling until the process is gone.
    KeepPolling,
    /// Nothing left that belongs to us.
    NothingLeft,
    /// The signal was refused or the pid could not be identified: the machine was not shut
    /// down.
    NotShutDown(String),
}

/// The teardown loop action implied by a kill attempt.
fn kill_step(outcome: &KillOutcome) -> KillStep {
    match outcome {
        KillOutcome::Killed => KillStep::KeepPolling,
        KillOutcome::Gone => KillStep::NothingLeft,
        KillOutcome::Refused(reason) => KillStep::NotShutDown(reason.clone()),
        KillOutcome::Unconfirmed(reason) => KillStep::NotShutDown(reason.clone()),
    }
}

/// Whether teardown keeps waiting, from one liveness scan of the QEMU pid.
///
/// Split from the loop so the scan's third answer is testable: `Ok(gone)` says whether the
/// process left, and `Err` says the scan could not look. Reading `Err` as "gone" is what
/// turned a hidden `/proc` into a clean shutdown of a live guest.
fn teardown_liveness(scan: std::io::Result<bool>, pid: u32) -> Result<bool> {
    match scan {
        Ok(gone) => Ok(!gone),
        Err(error) => bail!("{}", unconfirmed_liveness_message(pid, &error)),
    }
}

/// Message for a liveness check that could not look, which must never read like a shutdown.
///
/// This is the sibling of [`unkillable_message`] and [`kill_not_shut_down_message`]: all three
/// exist because the caller was about to claim that a machine stopped when nothing proved it.
fn unconfirmed_liveness_message(pid: u32, error: &std::io::Error) -> String {
    format!(
        "could not read the state of QEMU process {pid}: {error}\n\
         Qlean reports a machine shut down - and clears its pid - only after it saw the process \
         go, so this machine is still claimed and nothing was released. A host where /proc is \
         hidden (hidepid=2, a chroot, a sandbox) answers every process as gone, which would let \
         the next start rebuild the overlay of a live guest. Make /proc readable and try again"
    )
}

/// Message for a refused kill, which must never read like a completed shutdown.
fn kill_not_shut_down_message(pid: u32, reason: &str) -> String {
    format!(
        "QEMU process {pid} is still running: the machine was not shut down because SIGKILL \
         was refused ({reason}). Kill pid {pid} manually before starting it again"
    )
}

/// SIGKILL a pid only when it is still QEMU, reporting what actually happened.
///
/// The refusal case must stay distinguishable from the gone case: a callback that cannot
/// tell them apart reports success while the guest keeps its overlay open.
fn force_kill(pid: u32, socket_path: Option<&Path>) -> KillOutcome {
    force_kill_with(pid, socket_path, signal_kill)
}

/// `force_kill` with an injectable signal delivery, so the refusal path is testable against
/// a real process instead of a mock pid.
fn force_kill_with(
    pid: u32,
    socket_path: Option<&Path>,
    signal: impl FnMut(u32) -> std::io::Result<()>,
) -> KillOutcome {
    force_kill_using(
        pid,
        |pid| process_is_this_machines_qemu(pid, socket_path),
        signal,
    )
}

/// `force_kill_with` with the identity check injectable too: "this pid is not our QEMU" and
/// "this pid could not be identified" must not lead to the same place.
fn force_kill_using(
    pid: u32,
    identity: impl Fn(u32) -> std::io::Result<bool>,
    mut signal: impl FnMut(u32) -> std::io::Result<()>,
) -> KillOutcome {
    match identity(pid) {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                "not sending SIGKILL to pid {pid}: it no longer looks like the QEMU process Qlean started (the pid was probably reused)"
            );
            return KillOutcome::Gone;
        }
        Err(error) => {
            warn!(
                "not sending SIGKILL to pid {pid}: could not identify it as this machine's QEMU: {error}"
            );
            return KillOutcome::Unconfirmed(format!(
                "could not identify pid {pid} as this machine's QEMU: {error}"
            ));
        }
    }
    match signal(pid) {
        Ok(()) => KillOutcome::Killed,
        Err(error) => {
            warn!("failed to send SIGKILL to pid {pid}: {error}");
            KillOutcome::Refused(error.to_string())
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

/// Stop a QEMU process this crate started, best effort.
///
/// `SIGTERM` first so the guest gets a chance to shut down, then `SIGKILL` after a bounded
/// wait. Both signals go through the pid only while it still belongs to QEMU, because a
/// recycled pid would take an unrelated process down with it. Failures are warnings: this
/// runs on paths that are already returning an error, and a teardown that cannot finish must
/// not hide that error.
async fn terminate_qemu(pid: u32, socket_path: Option<&Path>) {
    match process_is_this_machines_qemu(pid, socket_path) {
        Ok(true) => {}
        Ok(false) => {
            warn!("QEMU pid {pid} is gone; nothing to terminate");
            return;
        }
        Err(error) => {
            // Signalling a pid that could not be identified would be a guess about whose
            // process it is; this path is already returning an error, so say so and leave it.
            warn!(
                "not terminating pid {pid}: could not identify it as this machine's QEMU: {error}"
            );
            return;
        }
    }
    if let Err(error) = signal_term(pid) {
        warn!("failed to send SIGTERM to QEMU pid {pid}: {error}");
    }

    // Give it a moment to exit; then SIGKILL.
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match process_is_gone(pid) {
            Ok(true) => return,
            // Leave it alone rather than SIGKILL a pid whose state cannot be read.
            Err(error) => {
                warn!("stopped waiting for QEMU pid {pid} to exit: {error}");
                return;
            }
            Ok(false) => {}
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if let KillOutcome::Refused(reason) = force_kill(pid, socket_path) {
        warn!("{}", kill_not_shut_down_message(pid, &reason));
    }
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

/// Message for the one teardown outcome that must never look like success.
///
/// Extracted so the wording is testable: the apostrophe-free sentence spans two source
/// lines, and a lost continuation silently turned it into one string with a run of spaces
/// in the middle of the user-visible error.
fn unkillable_message(pid: u32) -> String {
    format!(
        "QEMU process {pid} is still running after SIGKILL: the machine was not shut down. \
         Kill pid {pid} manually before starting it again"
    )
}

/// Convert a caller-supplied path into a validated guest path for `os`.
fn guest_path_from(os: GuestOs, path: &Path) -> Result<GuestPath> {
    let text = path.to_str().ok_or_else(|| {
        anyhow::anyhow!("guest path is not valid UTF-8 and cannot be sent over SFTP: {path:?}")
    })?;
    GuestPath::new(os, text)
}

/// Basename of a local path, as a UTF-8 name that can be joined onto a guest path.
/// Transfer one symbolic link to the guest, refusing it on a guest that cannot store it.
///
/// `upload` reaches a link two ways: as the path it was handed, and as an entry inside the
/// tree it was handed. Both are the same rule, so both go through this function - a second
/// copy is how the two cases drifted apart in the first place. A recreate that fails is an
/// error, never a silently successful upload.
async fn upload_symbolic_link(
    ssh: &mut Session,
    os: GuestOs,
    local_link: &Path,
    remote_link: &GuestPath,
) -> Result<()> {
    if os == GuestOs::Windows {
        bail!(
            "symbolic links are not supported when uploading to a Windows guest: {}",
            remote_link.as_str()
        );
    }
    let target = tokio::fs::read_link(local_link)
        .await
        .with_context(|| format!("failed to read the link at {:?}", local_link))?;
    if let Some(parent) = remote_link.parent() {
        ssh.create_dir_all(&parent).await?;
    }
    let sftp = ssh.get_sftp().await?;
    crate::ssh::create_symlink(sftp, remote_link.as_str(), &target.to_string_lossy())
        .await
        .with_context(|| {
            format!(
                "failed to recreate the symbolic link {}",
                remote_link.as_str()
            )
        })?;
    Ok(())
}

/// Render the relative path of a walked local entry as a guest path.
///
/// `to_string_lossy` is not a converter: it replaces every non-UTF-8 byte with `U+FFFD`, so
/// two entries that differ only in such a byte (`f\xff` and `f\xfe`) render as the same
/// guest name and the second upload silently overwrites the first. A guest path is a
/// `String`, so an entry that cannot be spelled cannot be uploaded at all - the error names
/// the component instead of uploading it under a different name.
pub(crate) fn guest_relative_path(rel: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(name) => parts.push(name.to_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "local path component {name:?} is not valid UTF-8, so it has no guest name; \
                     rename it to upload it (qlean will not upload it under a different name)"
                )
            })?),
            other => bail!("unsupported local path component {other:?} in {rel:?}"),
        }
    }
    Ok(parts.join("/"))
}

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
            // `Drop` cannot report an unavailable identity, so pass what can be computed: with
            // it, a recycled pid that runs somebody else's VM is left alone; without it the
            // `argv[0]` rule still applies, so a QEMU of ours is never left running.
            let identity = qmp::qmp_socket_path(&self.id).ok();
            force_kill(pid, identity.as_deref());
        }
        // Stop swtpm before the run dir disappears underneath its control socket; the
        // explicit take() makes the ordering deterministic instead of relying on field
        // drop order.
        if let Some(mut swtpm) = self.swtpm.take() {
            // The same promise the asynchronous teardown keeps: a TPM that is not confirmed gone
            // may still be writing the state directory this drop is about to remove, so it is
            // reported through the same sentence instead of assumed stopped.
            if !swtpm.stop_now() {
                warn!("{}", unconfirmed_swtpm_message(&self.id, "during the drop"));
            }
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
    /// A pid exists, the QMP socket is gone and the process is gone: a stale pid only.
    NoControlSocket,
    /// A pid exists, the QMP socket is gone, but the process is still our QEMU.
    LiveWithoutSocket,
    /// Both exist, so only QMP can answer.
    AskQmp,
}

fn running_check(pid_present: bool, socket_present: bool, qemu_alive: bool) -> RunningCheck {
    match (pid_present, socket_present, qemu_alive) {
        (false, _, _) => RunningCheck::NotRunning,
        (true, true, _) => RunningCheck::AskQmp,
        (true, false, true) => RunningCheck::LiveWithoutSocket,
        (true, false, false) => RunningCheck::NoControlSocket,
    }
}

/// What `MachinePool::init_all` and `MachinePool::spawn_all` must do for one machine.
///
/// Both pool entry points ask the same two questions - is this a Windows guest, and is its
/// one-time deployment still pending - and they answer them in opposite directions: a Linux
/// guest is initialized by both (`init` is its deployment path and can repeat), a Windows
/// guest is initialized only while its seed is pending, and spawned afterwards because the
/// seed is consumed exactly once. Written as two negations in two predicates, the four cases
/// were untested and one flipped `is_some` would send a deployed guest back to `init` (where
/// it is rejected) or spawn a guest whose `sshd` has no installed key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StartActions {
    pub(crate) init_all: Start,
    pub(crate) spawn_all: Start,
}

/// The start one pool entry point performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Start {
    Init,
    Spawn,
}

/// Route a start request for one machine. The only place that decides it.
pub(crate) fn start_actions(guest_os: GuestOs, deployment_pending: bool) -> StartActions {
    match (guest_os, deployment_pending) {
        // Linux has no one-time medium: `init` lays down a fresh cloud-init seed every time.
        (GuestOs::Linux, _) => StartActions {
            init_all: Start::Init,
            spawn_all: Start::Spawn,
        },
        // A pending Windows deployment can only be run by `init`; once it has run, `init`
        // is refused by design, so both entry points must spawn.
        (GuestOs::Windows, true) => StartActions {
            init_all: Start::Init,
            spawn_all: Start::Init,
        },
        (GuestOs::Windows, false) => StartActions {
            init_all: Start::Spawn,
            spawn_all: Start::Spawn,
        },
    }
}

/// How many transport failures in a row end the deployment-marker wait.
///
/// The failure-recovery matrix promises this number: three consecutive failures report the lost
/// session instead of waiting out the whole 900s budget. One success in between resets the count,
/// because a guest that keeps answering is deploying, not unreachable.
pub(crate) const MAX_CONSECUTIVE_MARKER_ERRORS: u32 = 3;

/// What one deployment-marker poll means for the wait loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerPoll {
    /// The marker is on disk: the guest is deployed.
    Deployed,
    /// The guest answered and has not finished deploying yet.
    NotYet,
    /// The probe could not reach the guest, which says nothing about the deployment.
    TransportError,
}

/// Classify one marker poll.
pub(crate) fn marker_poll_outcome(poll: &Result<bool>) -> MarkerPoll {
    match poll {
        Ok(true) => MarkerPoll::Deployed,
        Ok(false) => MarkerPoll::NotYet,
        Err(_) => MarkerPoll::TransportError,
    }
}

/// Count consecutive transport failures and say when the wait must end.
///
/// Kept apart from the loop so the counting rule is testable without a guest: counting all
/// failures instead of consecutive ones aborts a slow deployment, and never resetting does the
/// same for a boot that briefly loses sshd.
#[derive(Debug, Default)]
pub(crate) struct MarkerWatch {
    consecutive_errors: u32,
}

impl MarkerWatch {
    /// Feed one poll in; `true` means "give up now and report the transport error".
    pub(crate) fn observe(&mut self, poll: MarkerPoll) -> bool {
        match poll {
            MarkerPoll::TransportError => {
                self.consecutive_errors += 1;
                self.consecutive_errors >= MAX_CONSECUTIVE_MARKER_ERRORS
            }
            MarkerPoll::NotYet | MarkerPoll::Deployed => {
                self.consecutive_errors = 0;
                false
            }
        }
    }
}

/// Refuse to `init` a machine whose route is not `init`.
///
/// The pool decides a start with [`start_actions`]; the public entry point has to answer the
/// same question, or a caller reaches QEMU with a guest whose medium was already consumed and
/// learns it from a boot that hangs. The message names the way forward, because "already
/// completed" alone leaves the caller with a refused call and no next step.
fn init_guard(actions: StartActions, machine_id: &str) -> Result<()> {
    if actions.init_all == Start::Init {
        return Ok(());
    }
    bail!(
        "VM-{machine_id} already completed its Windows first-boot deployment; \
         use `spawn` to start it again"
    )
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
/// The two questions the pool asks a machine are the two columns of one table.
///
/// The table ([`start_actions`]) has its own four-row test, and the pool's call sites are
/// pinned separately - so the only thing left between them is these two one-line projections,
/// and *which column* each one reads had no test at all: swapping them (init asks `spawn_all`,
/// spawn asks `init_all`) left the whole suite green. The cost is not symmetric: a pending
/// Windows deployment that the pool sends to `spawn` boots a guest with no installed SSH key
/// and times out in the deployment wait, and a deployed one that the pool sends to `init` is
/// refused, because its seed medium is gone by design.
mod routing_tests {
    use super::*;

    /// A machine fixture with the given guest OS and deployment state.
    ///
    /// The seed is really staged (three small files, no `xorriso`), because the question under
    /// test is answered from `deploy_seed.is_some()` and not from a flag standing in for it.
    async fn machine(guest_os: GuestOs, deployment_pending: bool) -> Machine {
        let mut machine = Machine::for_tests_with_pid(None);
        machine.image.guest_os = guest_os;
        if deployment_pending {
            let run_dir = std::env::temp_dir().join(format!(
                "qlean-routing-tests-{}-{guest_os:?}",
                std::process::id()
            ));
            let host_key = PersistedSshKeypair {
                pubkey_str: String::new(),
                _pubkey_path: run_dir.join("id_ed25519.pub"),
                privkey_str: "host-key-material".to_string(),
                privkey_path: run_dir.join("id_ed25519"),
            };
            machine.deploy_seed = Some(
                windows::DeploySeed::stage(&run_dir, "ssh-ed25519 AAAA qlean", &host_key)
                    .await
                    .expect("stage a seed medium for the routing fixture"),
            );
        }
        machine
    }

    #[tokio::test]
    async fn each_pool_question_reads_its_own_column_of_the_start_table() {
        let rows = [
            (GuestOs::Linux, false),
            (GuestOs::Linux, true),
            (GuestOs::Windows, true),
            (GuestOs::Windows, false),
        ];
        for (guest_os, pending) in rows {
            let actions = start_actions(guest_os, pending);
            let machine = machine(guest_os, pending).await;
            assert_eq!(
                machine.wants_init(),
                actions.init_all == Start::Init,
                "`init_all` for a {guest_os:?} guest with a pending deployment = {pending}"
            );
            assert_eq!(
                machine.needs_first_boot(),
                actions.spawn_all == Start::Init,
                "`spawn_all` for a {guest_os:?} guest with a pending deployment = {pending}"
            );
        }
    }

    /// The two questions are not the same question worded twice.
    ///
    /// A test that only compared each accessor with its own column would still pass if both
    /// columns were equal on every row it looked at; this pins the one row where they differ.
    #[tokio::test]
    async fn a_linux_machine_wants_init_and_does_not_need_a_first_boot() {
        let linux = machine(GuestOs::Linux, false).await;
        assert!(
            linux.wants_init() && !linux.needs_first_boot(),
            "a Linux guest has a fresh cloud-init seed on every `init` and nothing pending on \
             `spawn`, so its two pool questions have different answers"
        );
        let windows = machine(GuestOs::Windows, true).await;
        assert!(
            windows.wants_init() && windows.needs_first_boot(),
            "a pending Windows deployment has to run before either entry point can boot"
        );
        let deployed = machine(GuestOs::Windows, false).await;
        assert!(
            !deployed.wants_init() && !deployed.needs_first_boot(),
            "a deployed Windows guest cannot run `init` again and needs no deployment, so both \
             questions are answered `spawn`"
        );
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    #[tokio::test]
    async fn a_failed_launch_leaves_a_machine_that_can_be_started_again() {
        // A launch that fails leaves the cancel token behind - it is the "a launch was begun"
        // marker. Reading it as "this machine is up" is what turned a failed start into one
        // that could never be retried (F174).
        let mut machine = Machine::for_tests_with_pid(None);
        machine.ssh_cancel_token = Some(CancellationToken::new());
        assert!(
            !machine.already_started(),
            "a leftover token with no pid and no session was read as a running machine"
        );

        machine.abandon_launch();
        assert!(
            machine.ssh_cancel_token.is_none(),
            "the retry still carries the token of the launch that failed"
        );
        assert!(!machine.already_started());
    }

    #[tokio::test]
    async fn a_failed_launch_teardown_leaves_nothing_behind() {
        // The three failure exits of a launch (no lease, no deployment confirmation, no
        // session) share one teardown, and it has to clear the state that `is_running` reads
        // and that the next `init`/`spawn` refuses on (F176).
        let mut machine = Machine::for_tests_with_pid(None);
        machine.ip = Some("10.0.0.5".to_string());
        let task = tokio::spawn(async {});
        tokio::task::yield_now().await;

        let started = std::time::Instant::now();
        machine.tear_down_failed_launch(task).await;

        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the teardown waited on a launch task that had already finished"
        );
        assert!(machine.ssh.is_none(), "the teardown kept a session");
        assert_eq!(machine.ip, None, "the teardown kept the leased address");
        assert_eq!(machine.pid, None, "the teardown kept a QEMU pid");
        assert!(machine.swtpm.is_none(), "the teardown kept the TPM");
    }

    #[test]
    fn a_machine_with_a_pid_or_a_session_is_already_started() {
        let mut machine = Machine::for_tests_with_pid(Some(4242));
        assert!(
            !machine.already_started(),
            "a pid without the launch token cannot come from `init` or `spawn`"
        );
        machine.ssh_cancel_token = Some(CancellationToken::new());
        assert!(
            machine.already_started(),
            "a machine with a launch token and a live pid was reported as not started"
        );
    }

    #[tokio::test]
    async fn shutting_down_a_machine_that_never_started_is_not_an_error() {
        // `shutdown_all` reaches this path when the liveness probe failed, which includes
        // "this machine never came up". Reporting that as a failure would make a pool with a
        // single failed launch look like it also failed to shut down.
        Machine::never_started_for_tests()
            .shutdown_if_started()
            .await
            .expect("a machine that never started has nothing to shut down");

        // The strict path keeps refusing it, so a caller that does expect a running guest is
        // still told the truth.
        let error = Machine::never_started_for_tests()
            .shutdown()
            .await
            .expect_err("must refuse");
        assert!(error.to_string().contains("not running"), "{error}");
    }
}

#[cfg(test)]
mod blank_command_tests {
    use super::*;

    #[tokio::test]
    async fn a_blank_command_is_refused_before_a_session_is_looked_up() {
        // The refusal is the whole point of the check: an empty line would reach the guest
        // shell as an empty request, and the user would get a `0` exit code for doing nothing.
        // It ran only in an `#[ignore]` smoke that needs a real Windows guest (DEP-01/02),
        // although nothing about it needs a guest at all.
        for blank in ["", "   ", "\n\t "] {
            let mut machine = Machine::for_tests_with_pid(None);
            let error = machine
                .exec(blank)
                .await
                .expect_err("a blank command must be refused");
            let text = error.to_string();
            assert!(
                text.contains("requires a non-empty command"),
                "a blank command must be refused for being blank, not for any other reason: {text}"
            );
            assert!(
                text.contains("empty shell request"),
                "the message must say what would have been sent instead: {text}"
            );
        }
        // The control: the same never-started machine gets past the blank check for a real
        // command, so the error above really was the blank check and not the session lookup.
        let mut machine = Machine::for_tests_with_pid(None);
        let error = machine
            .exec("whoami")
            .await
            .expect_err("a machine that never started has no session");
        assert!(
            !error.to_string().contains("requires a non-empty command"),
            "`whoami` must not be refused as blank: {error}"
        );
    }
}

#[cfg(test)]
mod pid_file_tests {
    use super::*;

    /// The launch must not read back a pid file left by a run that already died.
    ///
    /// `read_pid` is a "first number that parses" reader: it has no way to tell the pid of the
    /// QEMU that is starting now from the pid of the one recorded before it. That is fine as long
    /// as the caller cleared the file first, and this test pins both halves: the reader really
    /// does accept the stale value, and clearing first makes the only reachable value the new one.
    #[tokio::test]
    async fn a_pid_file_from_an_earlier_run_is_not_read_back_as_this_launch() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("qemu.pid");
        std::fs::write(&pid_file, "4242").expect("write the stale pid");

        // The defect: a launch that does not clear the file records this pid as its own, so the
        // identity check later refuses to signal the QEMU that is actually running.
        assert_eq!(
            read_pid(&pid_file).await.expect("the stale pid parses"),
            4242
        );

        clear_stale_pid_file(&pid_file)
            .await
            .expect("clearing an existing pid file");
        assert!(
            !pid_file.exists(),
            "the stale pid file survived the clear, so the next read can still adopt it"
        );

        // What the QEMU of this launch writes once it is spawned.
        std::fs::write(&pid_file, "5353").expect("write the new pid");
        assert_eq!(read_pid(&pid_file).await.expect("the new pid parses"), 5353);
    }

    #[tokio::test]
    async fn clearing_a_pid_file_that_was_never_written_is_not_a_failure() {
        let dir = tempfile::tempdir().expect("temp dir");
        clear_stale_pid_file(&dir.path().join("qemu.pid"))
            .await
            .expect("a missing pid file is success");
    }

    /// A pid file that cannot be removed must fail the launch, not be launched over.
    ///
    /// Reading a stale pid is the failure this guards; if the clear fails and the launch
    /// continues, the machine records the old pid and every later signal step reports "nothing
    /// left to kill" while the new QEMU keeps the overlay.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_pid_file_that_cannot_be_removed_fails_the_launch() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).expect("create the locked directory");
        let pid_file = locked.join("qemu.pid");
        std::fs::write(&pid_file, "4242").expect("write the stale pid");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
            .expect("lock the directory");

        let error = clear_stale_pid_file(&pid_file)
            .await
            .expect_err("a pid file that cannot be removed must not be ignored")
            .to_string();

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock the directory");
        assert!(error.contains("qemu.pid"), "{error}");
        assert!(error.contains("refusing to start"), "{error}");
    }
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    /// A machine whose socket path is unique to this test process, so the test never reads a
    /// socket left in the real `~/.qlean/runs/`.
    fn machine_with_pid(pid: Option<u32>) -> Machine {
        let mut machine = Machine::for_tests_with_pid(pid);
        machine.id = format!("liveness-{}", std::process::id());
        machine
    }

    /// A live process that looks exactly like this machine's QEMU in `/proc/<pid>/cmdline`.
    ///
    /// Two things make it *this* machine's QEMU, and they are the two things teardown checks:
    /// `argv[0]` is the QEMU name, and the argument list carries the machine's own QMP socket.
    /// `exec -a` sets an `argv[0]` that is not the program path, and the inner `bash` ignores the
    /// extra argument (it becomes `$0`), so the fixture stays alive for 30s.
    fn spawn_lookalike_qemu(socket: &std::path::Path) -> std::process::Child {
        let chardev = format!(
            "socket,path={},server=on,wait=off,id=qmp0",
            socket.display()
        );
        std::process::Command::new("bash")
            .arg("-c")
            // `sleep 30; :` and not `sleep 30`: bash execs a single simple command in place
            // of itself, which would replace the QEMU name this fixture exists for.
            .arg("exec -a qemu-system-x86_64 bash -c 'sleep 30; :' \"$0\"")
            .arg(chardev)
            .spawn()
            .expect("start the lookalike")
    }

    /// Spawn a just-copied program, retrying while the kernel says `Text file busy`.
    ///
    /// `fs::copy` closes the destination before it returns, but every other thread in this
    /// process can fork in between: the child inherits the still-open write descriptor, and
    /// Linux refuses to execute a file that any process holds open for writing until that child
    /// `exec`s (ETXTBSY). `cargo test` runs this module's tests in parallel with every other
    /// module that spawns a process, so the copy is not always executable the moment it lands -
    /// measured as one failed full-suite run in six, with `start the lookalike: Os { code: 26,
    /// kind: ExecutableFileBusy }`.
    fn spawn_beside_a_busy_copy(program: &std::path::Path) -> std::process::Child {
        let mut last = None;
        for _ in 0..200 {
            match std::process::Command::new(program).arg("30").spawn() {
                Ok(child) => return child,
                Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                    last = Some(error);
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("start the lookalike at {}: {error}", program.display()),
            }
        }
        panic!(
            "the copy at {} stayed unexecutable for two seconds: {}",
            program.display(),
            last.expect("the retry loop only leaves without a child after ETXTBSY")
        )
    }

    /// A copy that another process has open for writing is refused until it is closed.
    ///
    /// This is the failure the retry exists for, driven on purpose instead of waited for: while
    /// a write descriptor on the copy is open, `exec` fails with `Text file busy`. The first
    /// `spawn` therefore has to fail, and `spawn_beside_a_busy_copy` has to succeed once the
    /// descriptor is closed - which is the whole difference between the flaky test this replaced
    /// (one failed run in six) and a deterministic one.
    #[test]
    fn a_copy_open_for_writing_is_refused_until_it_is_closed() {
        let dir = std::env::temp_dir().join(format!("qlean-busy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the busy directory");
        let program = dir.join("qemu-system-x86_64");
        std::fs::copy("/bin/sleep", &program).expect("copy a program to the QEMU name");

        // Hold the copy open for writing, the way a forked child of another thread would.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&program)
            .expect("open the copy for writing");
        let refused = std::process::Command::new(&program).arg("30").spawn();
        let error = refused.expect_err("a program open for writing cannot be executed");
        assert_eq!(
            error.raw_os_error(),
            Some(libc::ETXTBSY),
            "the kernel must report `Text file busy`: {error}"
        );

        // Close it from another thread, so the retry sees a moving target rather than a state the
        // test has already finished with.
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(writer);
        });
        let mut child = spawn_beside_a_busy_copy(&program);
        closer.join().expect("the closing thread");
        let running = child.try_wait().expect("ask whether the copy is running");
        assert!(
            running.is_none(),
            "the retry must return a running child, not one that already exited"
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Wait until `/proc/<pid>/cmdline` names the lookalike.
    ///
    /// `spawn` returns as soon as the child is forked; until it `exec`s, its command line is
    /// still this test binary's, so the `argv[0]` check answers `false` and the first draft of
    /// this test failed about one run in five.
    fn wait_until_the_child_is_qemu(pid: u32, socket: &std::path::Path) {
        for _ in 0..200 {
            if process_is_this_machines_qemu(pid, Some(socket)).expect("this host can read /proc") {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the lookalike never appeared as QEMU in /proc/{pid}/cmdline");
    }

    #[tokio::test]
    async fn is_running_refuses_a_live_qemu_that_lost_its_socket() {
        // The state a hung or half-torn-down launch leaves behind. `false` here would let a
        // caller start a second QEMU on a disk the first one still owns, so the check has to
        // refuse instead of answering - and nothing but the decision table was tested.
        let machine = machine_with_pid(Some(0));
        let socket = qmp::qmp_socket_path(&machine.id).expect("a socket path");
        let mut child = spawn_lookalike_qemu(&socket);
        wait_until_the_child_is_qemu(child.id(), &socket);
        let machine = machine_with_pid(Some(child.id()));
        assert!(
            !socket.exists(),
            "the test's own run directory must not exist: {}",
            socket.display()
        );

        let error = machine
            .is_running()
            .await
            .expect_err("a live QEMU without its control socket is not `false`");
        let text = error.to_string();
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            text.contains("still has a live QEMU process"),
            "the refusal must say the process is what is still there: {text}"
        );
        assert!(
            text.contains("control socket at"),
            "the refusal must name the missing socket: {text}"
        );
        assert!(
            text.contains(&socket.display().to_string()),
            "the refusal must print the socket it looked for: {text}"
        );
    }

    #[tokio::test]
    async fn is_running_answers_false_when_the_recorded_pid_is_no_longer_our_qemu() {
        // A pid that exists but is not QEMU - the pid was reused, or QEMU already exited and
        // the socket went with it. This is the one case where a missing socket really is
        // proof, and the answer must be `false` rather than an error.
        let machine = machine_with_pid(Some(std::process::id()));
        assert!(
            !process_is_this_machines_qemu(std::process::id(), None).expect("proc"),
            "the test binary is not QEMU; the case is only meaningful if it says so"
        );
        assert!(
            !machine
                .is_running()
                .await
                .expect("a reused pid is not an error"),
            "a recorded pid that is not QEMU means the domain is gone"
        );
    }

    #[test]
    fn a_qemu_serving_another_machine_is_not_signalled() {
        // The case the identity check exists for. A recorded pid is reused by a QEMU that is
        // running somebody else's VM - the user's own guest, another checkout's smoke run.
        // Naming QEMU in `argv[0]` is true for that process too, so `argv[0]` alone sent it
        // SIGKILL; only the QMP socket it actually serves says whose QEMU it is.
        let base = std::env::temp_dir().join(format!("qlean-identity-{}", std::process::id()));
        let ours = base.join("ours/qmp.sock");
        let theirs = base.join("theirs/qmp.sock");
        let mut child = spawn_lookalike_qemu(&theirs);
        let pid = child.id();
        wait_until_the_child_is_qemu(pid, &theirs);

        assert_eq!(
            force_kill(pid, Some(&ours)),
            KillOutcome::Gone,
            "a QEMU that serves another machine is not this machine's QEMU"
        );
        assert!(
            !process_is_gone(pid).expect("this host can read /proc"),
            "the lookalike must still be running: nothing may be signalled"
        );

        // The control: addressed with the socket it does serve, the same process is killed.
        // Without this half the assertions above would also pass for a check that always
        // answers `false`, which would leave every real QEMU running at teardown.
        assert_eq!(force_kill(pid, Some(&theirs)), KillOutcome::Killed);
        let _ = child.wait();
        assert!(
            process_is_gone(pid).expect("this host can read /proc"),
            "the lookalike was killed"
        );
    }

    #[tokio::test]
    async fn is_running_answers_false_for_a_machine_that_never_started() {
        let machine = machine_with_pid(None);
        assert!(
            !machine
                .is_running()
                .await
                .expect("a machine that never started is not an error"),
            "a machine that never started is not running"
        );
    }
}

#[cfg(test)]
mod upload_name_tests {
    use super::*;

    #[cfg(unix)]
    fn os_path(bytes: &[u8]) -> PathBuf {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }

    #[test]
    fn a_tree_entry_keeps_its_name_on_the_guest() {
        // The walked paths arrive as host `Path`s; the guest spelling is the same name with
        // `/` between the components, on every guest.
        assert_eq!(
            guest_relative_path(Path::new("dir/sub/file name.txt")).unwrap(),
            "dir/sub/file name.txt"
        );
        assert_eq!(
            guest_relative_path(Path::new("dir/日本語.txt")).unwrap(),
            "dir/日本語.txt"
        );
        // The root of the walk has no relative path at all.
        assert_eq!(guest_relative_path(Path::new("")).unwrap(), "");
    }

    #[cfg(unix)]
    #[test]
    fn an_entry_that_is_not_valid_utf8_is_refused_by_name() {
        let error = guest_relative_path(&os_path(b"dir/f\xff"))
            .expect_err("a byte that is not UTF-8 has no guest name");
        let text = error.to_string();
        assert!(text.contains("not valid UTF-8"), "{text}");
        assert!(
            text.contains("f\\xff") || text.contains("\"f\\xFF\""),
            "the message must name the component that cannot be uploaded: {text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn two_entries_that_differ_only_in_a_non_utf8_byte_never_share_a_guest_name() {
        // `to_string_lossy` rendered both as `dir/f\u{fffd}`, so the second upload silently
        // overwrote the first and the tree on the guest did not mirror the local one.
        let a = guest_relative_path(&os_path(b"dir/f\xff"));
        let b = guest_relative_path(&os_path(b"dir/f\xfe"));
        assert!(a.is_err() && b.is_err(), "neither name can be spelled");
        // The control: the same names in valid UTF-8 are distinct and kept.
        assert_ne!(
            guest_relative_path(Path::new("dir/f\u{00ff}")).unwrap(),
            guest_relative_path(Path::new("dir/f\u{00fe}")).unwrap()
        );
    }
}

#[cfg(test)]
mod upload_target_tests {
    use super::*;
    use russh_sftp::{
        client::error::Error as SftpError,
        protocol::{Status, StatusCode},
    };

    fn status(code: StatusCode) -> SftpError {
        SftpError::Status(Status {
            id: 0,
            status_code: code,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    #[test]
    fn only_a_definite_no_answers_that_the_target_is_not_a_directory() {
        // A listing that worked is the yes.
        assert!(directory_answer(Ok(())).unwrap());

        // `NoSuchFile`: the name is free, so the caller's path is the file to write.
        // `Failure`: a version-3 server's answer when it will not list a plain file. Both are
        // the protocol saying there is no directory here, and both keep the old behaviour of
        // uploading to the path as given.
        assert!(!directory_answer(Err(status(StatusCode::NoSuchFile))).unwrap());
        assert!(!directory_answer(Err(status(StatusCode::Failure))).unwrap());
    }

    #[test]
    fn an_answer_that_is_not_a_no_is_reported_instead_of_read_as_one() {
        // A directory the user may not list is still a directory. Read as "not a directory",
        // the local file was aimed at the directory's own path - on a Windows guest the
        // difference between `C:\out` and `C:\out\file.txt` - and the upload then failed
        // against the directory instead of saying why the listing had not worked.
        let denied = directory_answer(Err(status(StatusCode::PermissionDenied)))
            .expect_err("a refused listing says nothing about the target");
        assert!(
            denied.to_string().contains("Permission denied"),
            "the server's own words must survive: {denied}"
        );

        // Nor is a timeout, a dropped connection or a packet the server should not have sent
        // an answer about the remote file system at all.
        for error in [
            SftpError::Timeout,
            SftpError::IO("connection lost".to_string()),
            SftpError::UnexpectedBehavior("readdir without a handle".to_string()),
        ] {
            let text = error.to_string();
            let reported = directory_answer(Err(error))
                .expect_err("an inconclusive answer cannot decide where a file goes");
            assert!(
                reported.to_string().contains(&text),
                "the reported error must be the server's: {reported} vs {text}"
            );
        }
    }

    #[test]
    fn the_upload_asks_the_new_question_and_not_can_this_be_listed() {
        // The call site is the defect this module's helpers exist for: `read_dir(..).is_ok()`
        // answered "is it a directory" with "can it be listed".
        let body = include_str!("machine.rs");
        // The listing call is spelled without its receiver here, so this scan does not find its
        // own text and report it as a defect.
        for (at, _) in body.match_indices("sftp.read_dir(") {
            let statement = &body[at..];
            let statement = statement
                .find(';')
                .map(|end| &statement[..end])
                .unwrap_or(statement);
            assert!(
                !statement.contains(".is_ok()"),
                "a listing result is folded into a yes/no answer again: {statement}"
            );
        }
        let upload_at = body
            .find("pub async fn upload<")
            .expect("machine.rs has no upload");
        let upload = &body[upload_at..upload_at + 4000];
        assert!(
            upload.contains("remote_is_a_directory(ssh, remote_path.as_str()).await?"),
            "upload no longer asks whether the target is a directory through the checked helper"
        );
    }
}

#[cfg(test)]
mod copy_target_tests {
    use super::*;
    use russh_sftp::{
        client::error::Error as SftpError,
        protocol::{FileAttributes, Status, StatusCode},
    };

    fn status(code: StatusCode) -> SftpError {
        SftpError::Status(Status {
            id: 0,
            status_code: code,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    fn attributes(mode: u32) -> FileAttributes {
        FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::default()
        }
    }

    #[test]
    fn only_a_definite_no_answers_that_the_copy_destination_is_not_a_directory() {
        // A destination that says what it is.
        assert!(destination_is_a_directory(Ok(attributes(0o040_755))).unwrap());
        assert!(!destination_is_a_directory(Ok(attributes(0o100_644))).unwrap());

        // A destination that is not there yet is the file the copy creates - and a version-3
        // server's generic `Failure` about a plain file is the same answer as for a listing.
        assert!(!destination_is_a_directory(Err(status(StatusCode::NoSuchFile))).unwrap());
        assert!(!destination_is_a_directory(Err(status(StatusCode::Failure))).unwrap());
    }

    #[test]
    fn an_answer_that_is_not_a_no_is_reported_instead_of_read_as_one() {
        // A destination the user may not look at may be a directory, and the copy cannot
        // assume it is not: `Copy-Item -Destination <dir>` on a Windows guest copies *into*
        // it, so a folded answer turns one file into two.
        let denied = destination_is_a_directory(Err(status(StatusCode::PermissionDenied)))
            .expect_err("a refused stat says nothing about the destination");
        assert!(
            denied.to_string().contains("Permission denied"),
            "the server's own words must survive: {denied}"
        );

        for error in [
            SftpError::Timeout,
            SftpError::IO("connection lost".to_string()),
            SftpError::UnexpectedBehavior("stat without a filename".to_string()),
        ] {
            let text = error.to_string();
            let reported = destination_is_a_directory(Err(error))
                .expect_err("an inconclusive answer cannot decide what the copy replaces");
            assert!(
                reported.to_string().contains(&text),
                "the reported error must be the server's: {reported} vs {text}"
            );
        }
    }

    #[test]
    fn the_copy_asks_the_new_question_and_not_can_this_be_stated() {
        const SOURCE: &str = include_str!("machine.rs");
        let at = SOURCE
            .find("pub async fn copy<")
            .expect("machine.rs has no copy");
        let rest = &SOURCE[at..];
        let body = &rest[..rest.find("pub async fn create_dir<").unwrap_or(rest.len())];
        // The shape, not a spelling: any single statement that both states a path and decides
        // whether it is a directory has to go through the checked helper. Pinning the old
        // spelling missed a re-spelled fold (that discovery is recorded as R197's negative
        // result), so the rule is about what the statement does.
        for (at, _) in body.match_indices("sftp.metadata(") {
            let start = body[..at].rfind('\n').map_or(0, |newline| newline + 1);
            let statement = &body[start..];
            let statement = statement
                .find(';')
                .map_or(statement, |end| &statement[..end]);
            let decides = statement.contains(".is_dir()") || statement.contains("Err(_)");
            assert!(
                !decides || statement.contains("destination_is_a_directory("),
                "the copy destination is classified by whether it could be stated again: \
                 {statement}"
            );
        }
        assert!(
            body.contains("destination_is_a_directory(sftp.metadata(to.as_str()).await)"),
            "the copy no longer asks whether its destination is a directory through the \
             checked helper"
        );
    }
}

#[cfg(test)]
mod download_target_tests {
    use super::*;

    /// Real answers from the host filesystem, not constructed ones.
    #[test]
    fn only_a_definite_no_answers_that_the_local_target_is_not_a_directory() {
        let dir = tempfile::tempdir().expect("temp dir");
        let plain = dir.path().join("file.txt");
        std::fs::write(&plain, b"x").expect("write");
        let missing = dir.path().join("absent");

        // The two answers the filesystem can give about a directory.
        assert!(host_target_is_a_directory(std::fs::metadata(dir.path())).unwrap());
        assert!(!host_target_is_a_directory(std::fs::metadata(&plain)).unwrap());

        // A name that does not exist is not a directory, and the download creates the file
        // exactly as it did before - the fix must not turn a new filename into an error.
        assert!(!host_target_is_a_directory(std::fs::metadata(&missing)).unwrap());

        // A path whose component is a file cannot be a directory either: the call fails, the
        // answer is still definite.
        let through_a_file = plain.join("child");
        assert!(!host_target_is_a_directory(std::fs::metadata(&through_a_file)).unwrap());
    }

    /// An answer that is not a no is reported instead of being read as one.
    #[cfg(unix)]
    #[test]
    fn a_host_path_that_cannot_be_inspected_is_reported() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("temp dir");
        // A symlink that points at itself: `metadata` follows links, so the kernel refuses with
        // `ELOOP` - nobody can say whether the target is a directory, and the download must not
        // decide on its own that it is a file.
        let looped = dir.path().join("loop");
        symlink(&looped, &looped).expect("symlink");
        let error = host_target_is_a_directory(std::fs::metadata(&looped))
            .expect_err("a symlink loop says nothing about the target");
        // `ErrorKind::FilesystemLoop` is still unstable, so the kernel's own number is checked:
        // ELOOP is the answer that must survive, in place of a fabricated "not a directory".
        assert_eq!(
            error.raw_os_error(),
            Some(libc::ELOOP),
            "the host's own answer has to survive: {error}"
        );
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn the_download_asks_the_new_question_and_not_can_this_be_statted() {
        const SOURCE: &str = include_str!("machine.rs");
        let at = SOURCE
            .find("pub async fn download<")
            .expect("machine.rs has no download");
        // Stop at the next method, so the scan covers `download` and nothing after it. The
        // needles are assembled at compile time: a literal here would be found in this file's
        // own text, which is exactly the trap that made an earlier guard pass on itself.
        let rest = &SOURCE[at..];
        let body = match rest[1..].find("\n    pub async fn ") {
            Some(end) => &rest[..end + 1],
            None => rest,
        };
        assert!(
            body.contains("host_target_is_a_directory(tokio::fs::metadata(local_path).await)"),
            "the download no longer asks whether the local target is a directory through the \
             checked helper"
        );
        // The old fold: any error from the host stat became "not a directory".
        let folds = [
            concat!("Ok(attr) if attr.is_dir()", " =>"),
            concat!("match tokio::fs::", "metadata("),
        ];
        for fold in folds {
            assert!(
                !body.contains(fold),
                "the local target is classified by whether it could be stated again: {fold}"
            );
        }
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn a_machine_counts_as_started_when_qemu_or_ssh_is_present() {
        // `shutdown` refuses a machine that never started, and `shutdown_if_started` uses the
        // same predicate when the liveness probe could not answer. Both are decided from
        // `pid`/`ssh`; getting this table wrong either leaks a running guest or reports a
        // spurious "not running" for a machine that was never started.
        assert!(started(true, true), "QEMU and SSH are both up");
        assert!(
            started(true, false),
            "a QEMU pid is enough proof of a start"
        );
        assert!(
            started(false, true),
            "a live SSH session is enough proof of a start"
        );
        assert!(
            !started(false, false),
            "nothing started means there is nothing to shut down"
        );
    }

    #[test]
    fn only_a_windows_first_boot_takes_the_shared_deadline() {
        // The shared deadline exists so one budget covers lease, `sshd` and deploy marker.
        // A restart draws on the plain connect budget instead: a machine that already booted
        // must not report a first-boot timeout (R244).
        assert!(
            takes_first_boot_deadline(true, GuestOs::Windows),
            "the Windows first boot is the case the deadline exists for"
        );
        assert!(
            !takes_first_boot_deadline(false, GuestOs::Windows),
            "a Windows restart keeps the plain connect budget"
        );
        assert!(
            !takes_first_boot_deadline(true, GuestOs::Linux),
            "a Linux first boot has no deployment to budget for"
        );
    }

    #[test]
    fn a_launch_starts_a_software_tpm_only_while_it_has_none() {
        // Overwriting the handle with a second `swtpm` drops the child that owns the socket
        // the guest's TPM 2.0 device was created against (R244).
        assert!(
            needs_swtpm_start(false),
            "a machine without a software TPM has to start one"
        );
        assert!(
            !needs_swtpm_start(true),
            "a restart must keep the `swtpm` the machine already started"
        );
    }

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

    #[test]
    fn a_qemu_exit_is_reported_as_the_cause_of_the_cancelled_launch() {
        // The defect: `launch_qemu` cancels the launch token before its task reports the
        // result, so the cancellation branch could win the `select!` race and tell the user
        // "launch was cancelled" for a guest whose QEMU had just failed to start. The
        // cancellation is the symptom; the QEMU outcome is the cause.
        let failed = qemu_exit_before_lease(Ok(Err(anyhow::anyhow!("bridge helper failed"))));
        let message = failed.to_string();
        assert!(
            message.contains("QEMU failed before the Windows guest obtained a DHCP lease"),
            "{message}"
        );
        assert!(
            message.contains("bridge helper failed"),
            "the QEMU reason must survive: {message}"
        );
        assert!(
            !message.contains("cancelled"),
            "a failed QEMU must not be reported as a cancellation: {message}"
        );

        let clean = qemu_exit_before_lease(Ok(Ok(())));
        assert!(
            clean
                .to_string()
                .contains("QEMU exited before the Windows guest obtained a DHCP lease"),
            "{clean}"
        );
    }

    #[test]
    fn the_first_boot_deadline_is_read_in_exactly_one_place() {
        // The bug: `confirm_deployment` computed its own remaining budget and fell back to a
        // *fresh* timeout when the deadline had expired, so a first boot could take twice the
        // documented budget. `remaining_first_boot_budget` is now the only reader; a new
        // direct `remaining_budget` call would be the same mistake in another phase.
        let source: &str = include_str!("machine.rs");
        // The test module counts itself too, so only the production half is scanned.
        let production = source.split("#[cfg(test)]").next().expect("module source");
        assert_eq!(
            production.matches("remaining_budget(").count(),
            2,
            "remaining_budget must only be defined and used by remaining_first_boot_budget"
        );
    }

    /// Doc-comment text (`/// ...`) that documents `declaration` in `source`.
    ///
    /// The lines are joined into one string because the README wraps its excerpt at a
    /// different column than the crate source; the wording, not the wrapping, is compared.
    fn doc_text_before(source: &str, declaration: &str) -> String {
        let lines: Vec<&str> = source.lines().collect();
        let end = lines
            .iter()
            .position(|line| line.trim() == declaration)
            .unwrap_or_else(|| panic!("`{declaration}` is not declared in the scanned file"));
        let mut docs: Vec<String> = Vec::new();
        for line in lines[..end].iter().rev() {
            let trimmed = line.trim();
            match trimmed.strip_prefix("///") {
                Some(rest) => docs.push(rest.trim().to_string()),
                // A blank line or an attribute above the field ends nothing: both can sit
                // between the doc comment and the declaration.
                None if docs.is_empty() && (trimmed.is_empty() || trimmed.starts_with("#[")) => {
                    continue;
                }
                None => break,
            }
        }
        docs.reverse();
        docs.join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn the_readme_documents_the_config_fields_the_way_the_crate_does() {
        // The bug: `ssh_timeout` was documented as "SSH over vsock" everywhere, including the
        // API excerpt in the README, while a Windows guest uses it as the budget for its
        // first-boot deployment. The README copy is not generated, so it drifted silently.
        // Compare the two verbatim.
        let readme = include_str!("../README.md");
        let machine_rs = include_str!("machine.rs");
        let image_rs = include_str!("image.rs");

        for (field, declaration, crate_docs) in [
            ("ssh_timeout", "pub ssh_timeout: Option<u64>,", machine_rs),
            ("guest_os", "pub guest_os: GuestOs,", image_rs),
        ] {
            let documented = doc_text_before(crate_docs, declaration);
            assert!(
                !documented.is_empty(),
                "`{field}` has no doc comment in the crate"
            );
            assert_eq!(
                doc_text_before(readme, declaration),
                documented,
                "the README's `{field}` doc comment drifted from the crate's"
            );
        }
    }

    #[test]
    fn an_expired_first_boot_budget_does_not_hand_out_a_fresh_one() {
        // The bug this guards: `confirm_deployment` turned an already-expired deadline into
        // `unwrap_or(timeout)`, so a guest that spent the whole budget reaching SSH got a
        // second full budget for the marker and a first boot could last twice as long as
        // documented.
        let expired = Some(std::time::Instant::now() - Duration::from_secs(1));
        let error = remaining_first_boot_budget(
            expired,
            Duration::from_secs(900),
            "the deployment marker appeared",
        )
        .expect_err("an expired budget must fail the phase, not restart it");
        let message = error.to_string();
        assert!(
            message.contains("the deployment marker appeared"),
            "{message}"
        );
        assert!(
            message.contains("not one phase"),
            "the failure must repeat that later phases get no fresh wait: {message}"
        );
    }

    #[test]
    fn a_running_first_boot_only_lends_the_next_phase_what_is_left() {
        let deadline = Some(std::time::Instant::now() + Duration::from_secs(5));
        let remaining =
            remaining_first_boot_budget(deadline, Duration::from_secs(900), "`sshd` answered")
                .expect("a future deadline still has budget");
        assert!(
            remaining <= Duration::from_secs(5),
            "a phase must not get more than what the shared deadline leaves: {remaining:?}"
        );
    }

    #[test]
    fn a_boot_that_is_not_a_first_boot_gets_the_plain_budget() {
        let budget = Duration::from_secs(180);
        assert_eq!(
            remaining_first_boot_budget(None, budget, "`sshd` answered").expect("no deadline"),
            budget
        );
    }

    #[tokio::test]
    async fn a_config_that_cannot_describe_a_machine_fails_before_anything_is_written() {
        let runs = crate::utils::QleanDirs::new().unwrap().runs;
        let count =
            |dir: &std::path::Path| std::fs::read_dir(dir).map(|it| it.count()).unwrap_or(0);
        let before = count(&runs);
        // The image path does not exist: validation must run before the overlay is built,
        // so the error talks about the config instead of a missing image.
        let image = crate::image::Image::for_tests(std::env::temp_dir().join("qlean-absent.qcow2"));
        let config = MachineConfig {
            mem: 0,
            ..MachineConfig::default()
        };
        let error = match Machine::new(&image, &config).await {
            Ok(_) => panic!("a config without memory must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("MachineConfig::mem"), "{error}");
        assert_eq!(
            count(&runs),
            before,
            "a rejected config must not leave a run directory behind"
        );
    }

    #[test]
    fn a_config_that_cannot_describe_a_machine_is_rejected_by_name() {
        let zero_core = MachineConfig {
            core: 0,
            ..MachineConfig::default()
        };
        let message = zero_core.validate().unwrap_err().to_string();
        assert!(message.contains("core"), "{message}");
        assert!(message.contains("at least 1"), "{message}");

        let zero_mem = MachineConfig {
            mem: 0,
            ..MachineConfig::default()
        };
        let message = zero_mem.validate().unwrap_err().to_string();
        assert!(message.contains("mem"), "{message}");

        let zero_disk = MachineConfig {
            disk: Some(0),
            ..MachineConfig::default()
        };
        let message = zero_disk.validate().unwrap_err().to_string();
        assert!(message.contains("disk"), "{message}");
        assert!(message.contains("truncate"), "{message}");

        let zero_budget = config(Some(0));
        let message = zero_budget.validate().unwrap_err().to_string();
        assert!(message.contains("ssh_timeout"), "{message}");
        assert!(message.contains("already spent"), "{message}");

        // A default config and a deliberate one-second budget stay valid.
        assert!(MachineConfig::default().validate().is_ok());
        assert!(config(Some(1)).validate().is_ok());
        assert!(
            MachineConfig {
                disk: Some(1),
                ..MachineConfig::default()
            }
            .validate()
            .is_ok()
        );
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
    fn unkillable_message_reads_as_one_sentence_and_names_the_pid() {
        let message = unkillable_message(4242);
        assert!(message.contains("still running after SIGKILL"), "{message}");
        assert!(message.contains("Kill pid 4242 manually"), "{message}");
        assert!(message.ends_with("again"), "{message}");
    }

    #[test]
    fn a_kill_step_never_turns_a_refusal_into_a_missing_process() {
        // The two "false" worlds of the old `bool` were "the pid is no longer ours" and
        // "our QEMU is still alive because SIGKILL was refused". Only the first may end
        // teardown quietly.
        assert_eq!(kill_step(&KillOutcome::Killed), KillStep::KeepPolling);
        assert_eq!(kill_step(&KillOutcome::Gone), KillStep::NothingLeft);
        assert_eq!(
            kill_step(&KillOutcome::Refused("Operation not permitted".into())),
            KillStep::NotShutDown("Operation not permitted".into())
        );
    }

    #[test]
    fn a_refused_kill_names_the_pid_and_the_reason() {
        let message = kill_not_shut_down_message(4242, "Operation not permitted (os error 1)");
        assert!(message.contains("still running"), "{message}");
        assert!(
            message.contains("was not shut down"),
            "a refusal must not read like a completed shutdown: {message}"
        );
        assert!(
            message.contains("Operation not permitted (os error 1)"),
            "the reason must travel with the failure: {message}"
        );
        assert!(message.contains("Kill pid 4242 manually"), "{message}");
    }

    /// Start a real process whose `argv[0]` looks like QEMU, so the kernel-level checks in
    /// `force_kill_with` see the same thing they see for a real QEMU.
    fn spawn_fake_qemu() -> Option<std::process::Child> {
        // `exec -a` (a bash builtin) sets argv[0]; a plain Rust `Command` cannot.
        let child = std::process::Command::new("bash")
            .arg("-c")
            .arg("exec -a qemu-system-x86_64 sleep 60")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        // Wait until the exec has replaced bash, so `/proc/<pid>/cmdline` is the QEMU name.
        for _ in 0..100 {
            if process_is_this_machines_qemu(child.id(), None).expect("this host can read /proc") {
                return Some(child);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    }

    #[test]
    fn a_refused_signal_leaves_the_live_process_reported_as_still_running() {
        let Some(mut child) = spawn_fake_qemu() else {
            eprintln!("SMOKE-UNAVAILABLE: cannot start a process with a qemu-system argv[0]");
            return;
        };
        let pid = child.id();
        let outcome = force_kill_with(pid, None, |_| {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        });
        match &outcome {
            KillOutcome::Refused(reason) => {
                assert!(
                    reason.contains("Operation not permitted"),
                    "the refusal reason must be kept: {reason}"
                );
            }
            other => panic!("a refused signal must not be reported as {other:?}"),
        }
        assert!(
            !process_is_gone(pid).expect("this host can read /proc"),
            "the fake QEMU was never signalled, so it must still be alive"
        );

        // The real signal path still works on the same process, which is what makes the
        // negative case above meaningful.
        assert_eq!(force_kill(pid, None), KillOutcome::Killed);
        let _ = child.wait();
        for _ in 0..200 {
            if process_is_gone(pid).expect("this host can read /proc") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("SIGKILL was delivered but pid {pid} is still there");
    }

    /// The end-to-end refusal path: `shutdown` must not report a clean stop for a QEMU it
    /// cannot signal.
    ///
    /// Needs a real `qemu-system*` argv[0] owned by another uid **and** a process that lacks
    /// CAP_KILL, which no ordinary checkout has. The recipe lives in the plan's R95 evidence;
    /// without `QLEAN_REFUSED_KILL_PID` this case reports itself as unavailable instead of
    /// pretending to have run.
    #[tokio::test]
    #[ignore = "needs a live qemu-named pid that this process cannot signal (QLEAN_REFUSED_KILL_PID)"]
    async fn test_a_refused_kill_is_not_reported_as_a_shutdown() {
        let Some(pid) = std::env::var("QLEAN_REFUSED_KILL_PID")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
        else {
            eprintln!("SMOKE-UNAVAILABLE: set QLEAN_REFUSED_KILL_PID to an unsignalable qemu pid");
            return;
        };
        assert!(
            process_is_this_machines_qemu(pid, None).expect("this host can read /proc"),
            "pid {pid} does not look like QEMU"
        );
        assert!(
            !process_is_gone(pid).expect("this host can read /proc"),
            "pid {pid} is already gone"
        );
        // Signal 0 asks the kernel about permission without delivering anything, so this
        // precondition check cannot hide the very refusal the test is about.
        // SAFETY: signal 0 only tests whether the process exists and is signalable.
        assert_ne!(
            unsafe { libc::kill(pid as libc::pid_t, 0) },
            0,
            "pid {pid} is signalable here, so this test cannot observe a refusal"
        );

        let mut machine = Machine::for_tests_with_pid(Some(pid));
        let error = machine
            .shutdown()
            .await
            .expect_err("a refused kill is not a shutdown");
        let message = error.to_string();
        assert!(message.contains("was not shut down"), "{message}");
        assert!(message.contains(&pid.to_string()), "{message}");
        assert!(
            !process_is_gone(pid).expect("this host can read /proc"),
            "the fake QEMU must still be running after the refusal"
        );
        assert_eq!(
            machine.pid,
            Some(pid),
            "a machine whose QEMU survived must keep its pid, or the next start rebuilds              the overlay of a live guest"
        );
    }

    #[test]
    fn a_pid_that_is_not_qemu_is_reported_as_gone_instead_of_killed() {
        // Our own test process is not QEMU, so nothing may be signalled and teardown has
        // nothing left to wait for.
        assert_eq!(force_kill(std::process::id(), None), KillOutcome::Gone);
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
    fn cmdline_is_this_machines_qemu_only_matches_this_machines_qemu() {
        let ours = Path::new("/home/me/.qlean/runs/vm-1/qmp.sock");
        let theirs = Path::new("/home/me/.qlean/runs/vm-2/qmp.sock");
        // The chardev argument Qlean builds, as QEMU receives it: one NUL-terminated argv entry.
        let chardev = |socket: &Path| {
            let mut cmdline = b"qemu-system-x86_64\0-machine\0q35,accel=kvm\0".to_vec();
            for arg in crate::qemu::qmp_chardev_args(socket).expect("qmp args") {
                cmdline.extend_from_slice(arg.as_bytes());
                cmdline.push(0);
            }
            cmdline
        };

        // Without an identity, `argv[0]` alone still answers: that is the `Drop` path, where
        // the run directory may be unavailable and a QEMU of ours must not be left running.
        assert!(cmdline_is_this_machines_qemu(
            b"qemu-system-x86_64\0-machine\0q35,accel=kvm\0-drive\0file=overlay.img\0",
            None
        ));
        assert!(cmdline_is_this_machines_qemu(
            b"/usr/bin/qemu-system-aarch64\0-name\0vm\0",
            None
        ));
        // The kernel's qemu-kvm symlink is QEMU as well.
        assert!(cmdline_is_this_machines_qemu(
            b"/usr/bin/qemu-kvm\0-machine\0pc\0",
            None
        ));

        // With an identity, the command line must also serve this machine's own QMP socket.
        assert!(cmdline_is_this_machines_qemu(&chardev(ours), Some(ours)));
        // The one case the check exists for: a recycled pid that is running somebody else's
        // QEMU. Naming QEMU is not enough, or the signal would take their VM down.
        assert!(!cmdline_is_this_machines_qemu(&chardev(theirs), Some(ours)));

        assert!(!cmdline_is_this_machines_qemu(b"", None));
        assert!(!cmdline_is_this_machines_qemu(
            b"/usr/bin/bash\0-c\0sleep 30\0",
            Some(ours)
        ));
        // A later argument mentioning qemu must not make another program look like QEMU, even
        // when that program has our socket path on its command line.
        assert!(!cmdline_is_this_machines_qemu(
            b"/usr/bin/tee\0/tmp/qemu-system-x86_64.log\0",
            None
        ));
        assert!(!cmdline_is_this_machines_qemu(
            b"/usr/bin/qemu-img\0convert\0/home/me/.qlean/runs/vm-1/qmp.sock\0",
            Some(ours)
        ));
        assert!(!cmdline_is_this_machines_qemu(
            b"/usr/bin/qemu-img\0create\0disk.qcow2\0",
            None
        ));
    }

    #[test]
    fn the_kill_check_recognises_the_socket_a_launch_really_passes_to_qemu() {
        // Two modules own halves of one fact. `launch_qemu` tells QEMU which QMP socket to
        // serve; `is_running`, `force_kill` and `terminate_qemu` look for that same socket on
        // the process command line. Each half used to build the path on its own, so nothing
        // failed when they drifted apart - and the check fails *closed*: a command line that
        // carries a socket the check does not expect reads as somebody else's QEMU, so a
        // SIGKILL is skipped, `shutdown` reports a clean stop and the surviving QEMU keeps the
        // overlay. Ask the real argument builder, not a copy of its strings, and ask it
        // against the path the teardown paths themselves look up: taking both sides from the
        // builder would make the assertion tautological.
        let vmid = "identity-uses-the-launched-socket";
        let (launched, args) = crate::qemu::qmp_socket_and_args(vmid).expect("qmp arguments");
        let expected = crate::qmp::qmp_socket_path(vmid).expect("the socket teardown looks for");
        let mut cmdline = b"qemu-system-x86_64\0-machine\0q35\0".to_vec();
        for arg in &args {
            cmdline.extend_from_slice(arg.as_bytes());
            cmdline.push(0);
        }
        assert_eq!(
            launched, expected,
            "the launch named a different socket than teardown looks for"
        );
        assert!(
            cmdline_is_this_machines_qemu(&cmdline, Some(&expected)),
            "QEMU was told to serve {} but the kill check does not recognise it: {args:?}",
            expected.display()
        );

        // The same command line must not match a second machine, or the check would accept
        // any QEMU at all and prove nothing.
        let other = crate::qmp::qmp_socket_path("identity-uses-another-socket")
            .expect("another socket path");
        assert_ne!(other, expected, "two machines must not share a socket path");
        assert!(!cmdline_is_this_machines_qemu(&cmdline, Some(&other)));
    }

    #[tokio::test]
    async fn a_stuck_teardown_step_is_abandoned_at_its_budget() {
        // The guest-stopped-answering case: the close future never resolves, so teardown must
        // give up on it and let the kill path run instead of hanging the caller.
        let started = std::time::Instant::now();
        let finished =
            bounded_teardown(Duration::from_millis(100), std::future::pending::<()>()).await;
        assert!(finished.is_none(), "a pending step must not finish");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the budget must end the wait, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_teardown_step_that_finishes_keeps_its_result() {
        let finished = bounded_teardown(Duration::from_secs(5), async { 7u8 }).await;
        assert_eq!(finished, Some(7));
    }

    #[test]
    fn process_state_reads_the_letter_after_the_command_name() {
        // Field 2 may contain parentheses and spaces; the state letter follows the last `)`.
        let stat = "  1234 (qemu-system-x86_64) S 1 1234 1234 0 -1 4194560";
        assert_eq!(process_state_of(stat), Some('S'));
        let stat = "  99 (odd)name) Z 1 1 1 0 -1 0";
        assert_eq!(process_state_of(stat), Some('Z'));
        assert_eq!(process_state_of("garbage"), None);
    }

    /// A private process table for the tests that must not depend on the host's `/proc`.
    fn fake_proc_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("qlean-proc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the fake process table");
        root
    }

    fn write_pid_file(root: &std::path::Path, pid: u32, name: &str, body: &str) {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(&dir).expect("create the pid entry");
        std::fs::write(dir.join(name), body).expect("write the pid entry");
    }

    #[test]
    fn a_process_table_that_cannot_be_read_is_not_a_gone_process() {
        // The whole round: a hidden `/proc` (`hidepid=2`, a chroot, a sandbox) must answer
        // "could not look", never "that process is gone". The second answer is what teardown
        // reports as a clean shutdown and what lets a launch reuse a live guest's overlay.
        let root = fake_proc_root("states");
        assert!(
            process_is_gone_in(&root, 4242).expect("an empty table is readable"),
            "an entry that is not there is a process that is gone"
        );
        write_pid_file(
            &root,
            4242,
            "stat",
            "4242 (qemu-system-x86_64) S 1 4242 4242 0 -1 0",
        );
        assert!(
            !process_is_gone_in(&root, 4242).expect("the table is readable"),
            "a running process is not gone"
        );
        write_pid_file(
            &root,
            4243,
            "stat",
            "4243 (qemu-system-x86_64) Z 1 4243 4243 0 -1 0",
        );
        assert!(
            process_is_gone_in(&root, 4243).expect("the table is readable"),
            "a zombie cannot be signalled back to life"
        );
        // `X`/`x` are the transient dead states some kernels report instead of `Z`.
        for dead in ['X', 'x'] {
            let stat = format!("4245 (qemu-system-x86_64) {dead} 1 4245 4245 0 -1 0");
            write_pid_file(&root, 4245, "stat", &stat);
            assert!(
                process_is_gone_in(&root, 4245).expect("the table is readable"),
                "{dead} is a dead state"
            );
        }
        // The `hidepid` case: the entry is there, reading it is refused.
        let unreadable = root.join("4244");
        std::fs::create_dir_all(unreadable.join("stat")).expect("make a directory where stat goes");
        let error = process_is_gone_in(&root, 4244)
            .expect_err("an entry that cannot be read is not evidence of anything");
        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory, "{error}");
    }

    #[test]
    fn a_command_line_that_cannot_be_read_is_not_somebody_elses_process() {
        // "Not our QEMU" licenses a launch to reuse the disk. A command line that exists but
        // cannot be read says nothing about the process, so it must not answer "not ours".
        let root = fake_proc_root("cmdline");
        assert!(
            !identity_in(&root, 4242, None).expect("an empty table is readable"),
            "a pid that left between two reads is not our QEMU"
        );
        write_pid_file(&root, 4242, "cmdline", "qemu-system-x86_64\0");
        assert!(
            identity_in(&root, 4242, None).expect("the table is readable"),
            "argv[0] names QEMU"
        );
        let unreadable = root.join("4243");
        std::fs::create_dir_all(unreadable.join("cmdline")).expect("make a directory for cmdline");
        let error = identity_in(&root, 4243, None)
            .expect_err("an unreadable command line must be reported, not answered");
        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory, "{error}");
    }

    #[test]
    fn a_liveness_check_that_could_not_look_never_reads_as_a_shutdown() {
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let message = unconfirmed_liveness_message(4242, &error);
        assert!(message.contains("4242"), "{message}");
        assert!(message.contains("permission denied"), "{message}");
        assert!(message.contains("still claimed"), "{message}");
        assert!(message.contains("nothing was released"), "{message}");
        assert!(
            message.contains("/proc"),
            "the fix must be named: {message}"
        );
    }

    #[test]
    fn a_liveness_scan_that_could_not_look_does_not_end_teardown() {
        // The three answers of the scan, and the one that used to be mistaken for the first.
        assert!(teardown_liveness(Ok(false), 4242).expect("alive"));
        assert!(!teardown_liveness(Ok(true), 4242).expect("gone"));
        let error = teardown_liveness(
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            4242,
        )
        .expect_err("a scan that could not look must not end teardown");
        assert!(error.to_string().contains("still claimed"), "{error}");
        assert!(error.to_string().contains("4242"), "{error}");
    }

    #[test]
    fn a_pid_that_could_not_be_identified_is_not_a_pid_that_left() {
        // The identity check is the guard that licenses SIGKILL. Its two "no" answers are
        // different: "somebody else's pid" needs no signal and no wait, "cannot tell" needs
        // both to stay unclaimed.
        let mut signalled = false;
        let outcome = force_kill_using(
            4242,
            |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            |_| {
                signalled = true;
                Ok(())
            },
        );
        assert!(!signalled, "an unidentified pid must not be signalled");
        assert!(
            matches!(&outcome, KillOutcome::Unconfirmed(reason) if reason.contains("4242")),
            "{outcome:?}"
        );
        assert!(
            matches!(kill_step(&outcome), KillStep::NotShutDown(_)),
            "an unidentified pid is not a machine that shut down"
        );

        let outcome = force_kill_using(
            4242,
            |_| Ok(false),
            |_| {
                signalled = true;
                Ok(())
            },
        );
        assert!(!signalled, "somebody else's pid must not be signalled");
        assert_eq!(outcome, KillOutcome::Gone);
        assert_eq!(kill_step(&outcome), KillStep::NothingLeft);
    }

    #[test]
    fn a_killed_unreaped_child_counts_as_gone() {
        // A zombie keeps its `/proc/<pid>` entry: teardown must not wait out its budget for a
        // process that can no longer do anything.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a child to kill");
        let pid = child.id();
        assert!(
            !process_is_gone(pid).expect("this host can read /proc"),
            "a running child is not gone"
        );
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        // SAFETY: the pid belongs to the child we just spawned.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        // Do not reap yet: this is exactly the zombie state teardown must recognise.
        let mut gone = false;
        for _ in 0..200 {
            if process_is_gone(pid).expect("this host can read /proc") {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.wait();
        assert!(gone, "a killed but unreaped child must count as gone");
        assert!(
            process_is_gone(u32::MAX).expect("this host can read /proc"),
            "a missing pid is gone"
        );
    }

    #[test]
    fn process_is_this_machines_qemu_rejects_the_current_test_process() {
        // Guards the guard: the test binary is not QEMU, and the helper must say so, so a
        // recycled pid never gets SIGKILLed.
        assert!(
            !process_is_this_machines_qemu(std::process::id(), None)
                .expect("this host can read /proc")
        );
        assert!(!process_is_this_machines_qemu(u32::MAX, None).expect("this host can read /proc"));
    }

    #[test]
    fn user_facing_messages_have_no_runs_of_spaces() {
        // A lost `\` continuation leaves a run of spaces in the middle of a sentence, which
        // reads like a formatting bug to the user. This is a regression guard for that.
        let messages = [
            spawn_guard(true, "abc123").unwrap_err().to_string(),
            not_running_error("upload files", "abc123").to_string(),
            // This one shipped with a 30-space hole where a `\` continuation was meant to
            // be, and the guard did not list it, so nothing caught it.
            unkillable_message(4242),
            kill_not_shut_down_message(4242, "Operation not permitted (os error 1)"),
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
    fn every_pool_start_routes_a_pending_windows_deployment_through_init() {
        // The failure-recovery matrix promises that `init_all` spawns an already-deployed
        // Windows guest and that `spawn_all` deploys a pending one. Both are this table.
        let rows = [
            (GuestOs::Linux, false, Start::Init, Start::Spawn),
            (GuestOs::Linux, true, Start::Init, Start::Spawn),
            (GuestOs::Windows, true, Start::Init, Start::Init),
            (GuestOs::Windows, false, Start::Spawn, Start::Spawn),
        ];
        for (guest_os, pending, init_all, spawn_all) in rows {
            let actions = start_actions(guest_os, pending);
            assert_eq!(
                (actions.init_all, actions.spawn_all),
                (init_all, spawn_all),
                "init_all/spawn_all for a {guest_os:?} guest with deployment_pending={pending}"
            );
        }
    }

    #[test]
    fn the_marker_wait_gives_up_on_the_third_consecutive_transport_error() {
        let mut watch = MarkerWatch::default();
        assert!(!watch.observe(MarkerPoll::TransportError), "first");
        assert!(!watch.observe(MarkerPoll::TransportError), "second");
        assert!(watch.observe(MarkerPoll::TransportError), "third");

        // A guest that answers resets the count: three failures spread over a boot that keeps
        // reporting "not deployed yet" are not three failures in a row.
        let mut watch = MarkerWatch::default();
        for round in 0..5 {
            assert!(!watch.observe(MarkerPoll::TransportError), "round {round}");
            assert!(!watch.observe(MarkerPoll::TransportError), "round {round}");
            assert!(!watch.observe(MarkerPoll::NotYet), "round {round}");
        }

        // Two failures, one answer, two failures: still not three in a row.
        let mut watch = MarkerWatch::default();
        assert!(!watch.observe(MarkerPoll::TransportError));
        assert!(!watch.observe(MarkerPoll::TransportError));
        assert!(!watch.observe(MarkerPoll::Deployed));
        assert!(!watch.observe(MarkerPoll::TransportError));
        assert!(!watch.observe(MarkerPoll::TransportError));
    }

    #[test]
    fn a_marker_poll_is_classified_by_what_it_tells_the_wait() {
        // The wait ends on `Ok(true)` and must not treat "answered no" as an error: that would
        // abort every slow first boot on its third poll instead of its third failure.
        assert_eq!(marker_poll_outcome(&Ok(true)), MarkerPoll::Deployed);
        assert_eq!(marker_poll_outcome(&Ok(false)), MarkerPoll::NotYet);
        assert_eq!(
            marker_poll_outcome(&Err(anyhow::anyhow!("the session is gone"))),
            MarkerPoll::TransportError
        );
        assert_eq!(MAX_CONSECUTIVE_MARKER_ERRORS, 3);
    }

    #[test]
    fn init_is_refused_once_the_windows_deployment_has_run() {
        let refused = init_guard(start_actions(GuestOs::Windows, false), "abc123")
            .expect_err("a deployed guest must not be initialized again")
            .to_string();
        assert!(refused.contains("VM-abc123"), "{refused}");
        assert!(refused.contains("`spawn`"), "{refused}");
        for actions in [
            start_actions(GuestOs::Windows, true),
            start_actions(GuestOs::Linux, false),
            start_actions(GuestOs::Linux, true),
        ] {
            assert!(
                init_guard(actions, "abc123").is_ok(),
                "{actions:?} must still be initializable"
            );
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
        assert_eq!(running_check(false, false, false), RunningCheck::NotRunning);
        // A stale pid without a socket is still "not running".
        assert_eq!(running_check(false, true, false), RunningCheck::NotRunning);
        assert_eq!(
            running_check(true, false, false),
            RunningCheck::NoControlSocket
        );
        // Only here may a QMP failure be reported instead of "not running".
        assert_eq!(running_check(true, true, false), RunningCheck::AskQmp);
    }

    #[test]
    fn a_live_qemu_without_its_socket_is_not_a_dead_domain() {
        // The socket is a file; its absence says nothing about the process. Reporting
        // "not running" here would let `spawn` start a second QEMU on the same overlay.
        assert_eq!(
            running_check(true, false, true),
            RunningCheck::LiveWithoutSocket
        );
        // A live QEMU with a socket still goes to QMP, which decides.
        assert_eq!(running_check(true, true, true), RunningCheck::AskQmp);
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
