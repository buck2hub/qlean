use std::{
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, bail};
use console::strip_ansi_codes;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::{
    MachineConfig,
    firmware::VmFirmware,
    image::{GuestArch, GuestOs},
    is_kvm_available,
    machine::MachineImage,
    utils::{CommandExt, QLEAN_BRIDGE_NAME, QleanDirs},
};

/// Optional wall-clock limit for waiting on the QEMU process.
///
/// Unset or `0` = wait until QEMU exits (required for keep-alive VMs).
/// Set `QLEAN_QEMU_TIMEOUT_SECS` to a positive value only for bounded test runs.
fn resolve_qemu_wait_timeout() -> Option<Duration> {
    match std::env::var("QLEAN_QEMU_TIMEOUT_SECS") {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(secs) => Some(Duration::from_secs(secs)),
            Err(_) => {
                warn!(
                    value = %raw,
                    "invalid QLEAN_QEMU_TIMEOUT_SECS, waiting indefinitely for QEMU"
                );
                None
            }
        },
        Err(_) => None,
    }
}

pub(crate) fn qemu_system_program(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Amd64 => "qemu-system-x86_64",
        GuestArch::Aarch64 => "qemu-system-aarch64",
        GuestArch::Riscv64 => "qemu-system-riscv64",
    }
}

fn host_arch() -> Option<GuestArch> {
    match std::env::consts::ARCH {
        "x86_64" => Some(GuestArch::Amd64),
        "aarch64" => Some(GuestArch::Aarch64),
        "riscv64" => Some(GuestArch::Riscv64),
        _ => None,
    }
}

pub(crate) struct QemuLaunchParams {
    pub expected_to_exit: Arc<AtomicBool>,
    pub cid: u32,
    pub image: MachineImage,
    pub config: MachineConfig,
    pub vmid: String,
    pub is_init: bool,
    pub cancel_token: CancellationToken,
    pub mac_address: String,
    /// OVMF firmware for Windows guests.
    pub firmware: Option<VmFirmware>,
    /// swtpm control socket for Windows guests.
    pub tpm_socket: Option<PathBuf>,
}

/// Acceleration choice for a launch.
#[derive(Debug, PartialEq, Eq)]
enum Accel {
    Kvm,
    Tcg,
}

/// Pick an accelerator, refusing the TCG fallback for Windows guests.
fn select_accel(
    kvm_available: bool,
    host_matches: bool,
    guest_os: GuestOs,
) -> anyhow::Result<Accel> {
    if kvm_available && host_matches {
        return Ok(Accel::Kvm);
    }
    if guest_os == GuestOs::Windows {
        // Windows guests are KVM-only: never silently degrade to TCG emulation.
        bail!(
            "Windows guests require KVM acceleration on a host with a matching architecture; \
             KVM is unavailable or the host cannot run this guest architecture, and TCG \
             emulation is not supported for Windows guests"
        );
    }
    Ok(Accel::Tcg)
}

/// QEMU arguments for a Windows guest's firmware and TPM 2.0 device.
///
/// Windows boots only on UEFI. Secure Boot additionally needs SMM and the secure
/// pflash property; the resolution step reports which OVMF build was found instead
/// of silently downgrading the firmware.
fn windows_firmware_args(
    firmware: &VmFirmware,
    tpm_socket: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    let mut args = vec![
        "-machine".to_string(),
        if firmware.secure_boot {
            "q35,hpet=off,smm=on".to_string()
        } else {
            "q35,hpet=off".to_string()
        },
    ];
    if firmware.secure_boot {
        args.push("-global".to_string());
        args.push("driver=cfi.pflash01,property=secure,value=on".to_string());
    }
    args.push("-drive".to_string());
    args.push(format!(
        "if=pflash,format=raw,unit=0,readonly=on,file={}",
        qemu_option_path("OVMF code image", &firmware.code)?
    ));
    args.push("-drive".to_string());
    args.push(format!(
        "if=pflash,format=raw,unit=1,file={}",
        qemu_option_path("OVMF vars image", &firmware.vars)?
    ));
    if let Some(socket) = tpm_socket {
        args.push("-chardev".to_string());
        args.push(format!(
            "socket,id=chrtpm,path={}",
            qemu_option_path("swtpm control socket", socket)?
        ));
        args.push("-tpmdev".to_string());
        args.push("emulator,id=tpm0,chardev=chrtpm".to_string());
        args.push("-device".to_string());
        args.push("tpm-tis,tpmdev=tpm0".to_string());
    }
    Ok(args)
}

/// Render a host path for a comma-separated QEMU option value.
///
/// QEMU splits `-drive`/`-chardev` values on commas, so a path containing one would be
/// read as extra key=value pairs instead of a file name — QEMU would then either refuse
/// to start with a confusing message, or honour an injected property such as
/// `cache=unsafe`. Spaces are fine (the value is a single argv element), so only the
/// separators and control characters that break the encoding are rejected.
fn qemu_option_path(kind: &str, path: &Path) -> anyhow::Result<String> {
    let text = path.to_string_lossy().into_owned();
    if text.is_empty() {
        anyhow::bail!("{kind} path is empty");
    }
    if text.contains(',') {
        anyhow::bail!(
            "{kind} path `{text}` contains a comma, which QEMU would read as an option separator; \
             move it to a path without commas"
        );
    }
    if text.chars().any(|c| c.is_control()) {
        anyhow::bail!("{kind} path `{text}` contains a control character");
    }
    Ok(text)
}

/// QEMU arguments for the guest transport.
///
/// Only Linux guests speak `vsock`. A Windows guest has no vsock driver, and attaching
/// `vhost-vsock-pci` would additionally require `/dev/vhost-vsock` plus the
/// `vhost_vsock` module on the host, so QEMU would refuse to start on a host that is
/// perfectly able to run a Windows guest.
fn vsock_args(guest_os: GuestOs, cid: u32) -> Vec<String> {
    if guest_os == GuestOs::Windows {
        return Vec::new();
    }
    vec![
        "-device".to_string(),
        format!("vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={cid}"),
    ]
}

/// Serve QMP on `socket` and expose it as monitor `qmp0`.
///
/// Kept separate from [`launch_qemu`] so the exact channel string qlean relies on can be
/// handed to a real QEMU in a test: a typo here makes every shutdown fall back to SIGKILL
/// and every `is_running` check report a dead VM.
fn qmp_chardev_args(socket: &Path) -> anyhow::Result<Vec<String>> {
    Ok(vec![
        "-chardev".to_string(),
        format!(
            "socket,path={},server=on,wait=off,id=qmp0",
            qemu_option_path("QMP socket", socket)?
        ),
        "-mon".to_string(),
        "chardev=qmp0,mode=control".to_string(),
    ])
}

/// `-netdev` argument that puts the guest on the network Qlean reads DHCP leases from.
fn netdev_option() -> String {
    format!("bridge,id=net0,br={QLEAN_BRIDGE_NAME}")
}

/// `-device` argument for the guest NIC, carrying the MAC Qlean looks up in DHCP leases.
///
/// The MAC is the only link between this NIC and the lease Qlean waits for on a Windows
/// first boot, and it is generated independently of QEMU. If the guest ended up with a
/// different MAC, the lease search would never match and the failure would only surface as
/// a spent deployment budget, so the argument is shared with a real-QEMU test that asks the
/// monitor which MAC the NIC actually has.
fn nic_device_option(mac_address: &str) -> String {
    format!("virtio-net-pci,netdev=net0,mac={mac_address}")
}

/// `-drive` argument that attaches the first-boot seed medium.
///
/// Kept separate from [`launch_qemu`] for the same reason as [`qmp_chardev_args`]: the exact
/// string can then be handed to a real QEMU and asked what it realized. The IDE attachment is
/// deliberate — some images do not reliably scan virtio CD-ROM paths during early boot, so a
/// Windows guest that silently stops seeing the seed would spend its whole deployment budget
/// waiting for a marker it can never read.
fn seed_drive_option(seed: &Path) -> anyhow::Result<String> {
    Ok(format!(
        "file={},if=ide,media=cdrom,readonly=on",
        qemu_option_path("seed ISO", seed)?
    ))
}

/// `-drive` argument for the per-VM disk overlay.
///
/// Extracted for the same reason as [`seed_drive_option`]: the exact string is part of the
/// argument list a real QEMU is asked to realize, so the disk the guest boots from cannot
/// drift away from the one the tests ran.
fn disk_drive_option(overlay: &Path) -> anyhow::Result<String> {
    Ok(format!(
        "file={},if=virtio,cache=writeback",
        qemu_option_path("guest disk overlay", overlay)?
    ))
}

/// `-chardev` argument that tees the serial console into the run directory.
///
/// The console is the guest's own account of a first boot that never finished, so the
/// argument that captures it is shared with the real-QEMU launch test as well.
fn serial_chardev_option(log: &Path) -> anyhow::Result<String> {
    Ok(format!(
        "stdio,id=char0,mux=on,signal=off,logfile={},logappend=on",
        qemu_option_path("serial log", log)?
    ))
}

pub(crate) async fn launch_qemu(params: QemuLaunchParams) -> anyhow::Result<()> {
    // Prepare QEMU command
    let is_windows = params.image.guest_os == GuestOs::Windows;

    let mut qemu_cmd = tokio::process::Command::new(qemu_system_program(params.image.arch));
    if is_windows {
        let firmware = params.firmware.as_ref().with_context(
            || "Windows guest launched without OVMF firmware; internal invariant violated",
        )?;
        qemu_cmd.args(windows_firmware_args(
            firmware,
            params.tpm_socket.as_deref(),
        )?);
    } else if params.image.arch == GuestArch::Amd64 {
        // Decrease idle CPU usage on x86_64.
        qemu_cmd.args(["-machine", "hpet=off"]);
    }

    qemu_cmd.args(vsock_args(params.image.guest_os, params.cid));

    let dirs = QleanDirs::new()?;
    let run_dir = dirs.runs.join(&params.vmid);
    let qmp_socket = run_dir.join("qmp.sock");
    if qmp_socket.exists() {
        let _ = std::fs::remove_file(&qmp_socket);
    }

    qemu_cmd.args(qmp_chardev_args(&qmp_socket)?);

    let disk_drive = disk_drive_option(&params.image.overlay)?;
    qemu_cmd
        // Disk
        .args(["-drive", &disk_drive])
        // No GUI
        .arg("-nographic");

    qemu_cmd
        .args(["-netdev", &netdev_option()])
        .args(["-device", &nic_device_option(&params.mac_address)]);

    // Memory and CPUs
    qemu_cmd
        .args(["-m", &params.config.mem.to_string()])
        .args(["-smp", &params.config.core.to_string()]);

    // Output redirection
    // We multiplex QEMU monitor + guest serial onto stdio AND tee it into a file under the run dir.
    let serial_log = run_dir.join("serial.log");
    let serial_chardev = serial_chardev_option(&serial_log)?;
    qemu_cmd
        .args(["-chardev", &serial_chardev])
        .args(["-serial", "chardev:char0"])
        .args(["-mon", "chardev=char0,mode=readline"]);

    // Seed ISO is only used for initial boot with cloud-init.
    if params.is_init {
        qemu_cmd.args(["-drive", &seed_drive_option(&params.image.seed)?]);
    }

    match select_accel(
        is_kvm_available(),
        host_arch() == Some(params.image.arch),
        params.image.guest_os,
    )? {
        Accel::Kvm => {
            qemu_cmd.args(["-accel", "kvm"]).args(["-cpu", "host"]);
        }
        Accel::Tcg => {
            qemu_cmd.args(["-accel", "tcg"]);
            warn!(
                "KVM acceleration is unavailable for this host/guest architecture pair. Falling back to TCG emulation, which may be slower."
            );
        }
    }

    // Spawn QEMU process
    debug!("QEMU command: {:?}", qemu_cmd.to_string());
    let mut qemu_child = qemu_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    // Store QEMU PID
    let pid = qemu_child.id().expect("failed to get QEMU PID");
    let pid_file_path = run_dir.join("qemu.pid");
    tokio::fs::write(pid_file_path, pid.to_string()).await?;

    // Capture and log stdout
    let stdout = qemu_child.stdout.take().expect("Failed to capture stdout");
    let stdout_task = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            trace!("{}", strip_ansi_codes(&line));
        }
    });

    // Capture and log stderr, and keep a bounded tail of it.
    //
    // QEMU explains its own refusals on stderr (`qemu-system-x86_64: Could not open
    // '/dev/kvm': Permission denied`, `UNIX socket path ... is too long`), but that text
    // used to reach the log only. A caller left with "QEMU exited with status 1; check its
    // log for the reason" has to go hunting for a log file, and a Windows first boot
    // reports that same blank reason after burning its whole deployment budget. The tail
    // lets the exit error carry the cause it was already given (F96).
    let stderr_tail = new_stderr_tail();
    let stderr = qemu_child.stderr.take().expect("Failed to capture stderr");
    let tail_for_task = Arc::clone(&stderr_tail);
    let stderr_task = tokio::spawn(async move { capture_stderr(stderr, tail_for_task).await });

    let waited: std::result::Result<std::process::ExitStatus, anyhow::Error> =
        match resolve_qemu_wait_timeout() {
            Some(limit) => match timeout(limit, qemu_child.wait()).await {
                Err(_) => {
                    error!(
                        "QEMU process timed out after {} seconds; killing process before cancelling SSH",
                        limit.as_secs()
                    );
                    // Ensure the guest is gone before sticky-canceling SSH. Previously a
                    // hard-coded 6h wait timeout cancelled the token while QEMU could still
                    // be alive, leaving keep-alive VMs "running" with dead Machine::exec.
                    let _ = qemu_child.kill().await;
                    let _ = qemu_child.wait().await;
                    Err(anyhow::anyhow!(
                        "QEMU process timed out after {} seconds",
                        limit.as_secs()
                    ))
                }
                Ok(Err(e)) => {
                    error!("Failed to wait for QEMU: {}", e);
                    Err(e.into())
                }
                Ok(Ok(status)) => Ok(status),
            },
            None => match qemu_child.wait().await {
                Err(e) => {
                    error!("Failed to wait for QEMU: {}", e);
                    Err(e.into())
                }
                Ok(status) => Ok(status),
            },
        };

    // Cancel any ongoing operations due to QEMU exit (or intentional kill after timeout)
    params.cancel_token.cancel();

    // Wait for logging tasks to complete. The stderr tail has to be complete before the
    // exit status is described, otherwise the reason would be read while QEMU's last
    // words are still in flight.
    let _ = tokio::join!(stdout_task, stderr_task);

    qemu_exit_result(waited, pid, &params.expected_to_exit, &stderr_tail)
}

/// Turn the wait outcome and the captured stderr tail into the reported result.
///
/// Kept separate from `launch_qemu` so that the wiring ("the tail actually reaches the
/// error") is testable without booting a guest: a version of this function that drops
/// `reason` on the floor would leave every test green while users keep reading
/// `exited with status 1; check its log`.
fn qemu_exit_result(
    waited: std::result::Result<std::process::ExitStatus, anyhow::Error>,
    pid: u32,
    expected_to_exit: &Arc<AtomicBool>,
    tail: &StderrTail,
) -> anyhow::Result<()> {
    match waited {
        Ok(status) => {
            let reason = stderr_reason(tail);
            map_qemu_exit_status(status, pid, expected_to_exit, reason.as_deref())
        }
        Err(error) => Err(error),
    }
}

/// How many trailing QEMU stderr lines may travel with an exit error.
const STDERR_TAIL_LINES: usize = 10;
/// Longest stderr line kept verbatim; QEMU can echo a whole command line.
const STDERR_TAIL_WIDTH: usize = 400;

/// The trailing QEMU stderr lines, shared between the reader task and the exit report.
type StderrTail = Arc<std::sync::Mutex<std::collections::VecDeque<String>>>;

fn new_stderr_tail() -> StderrTail {
    Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()))
}

fn push_stderr_line(tail: &StderrTail, line: &str) {
    let line = line.trim_end();
    if line.is_empty() {
        return;
    }
    let line = if line.chars().count() > STDERR_TAIL_WIDTH {
        let cut: String = line.chars().take(STDERR_TAIL_WIDTH).collect();
        format!("{cut}…")
    } else {
        line.to_string()
    };
    // A poisoned lock still holds usable data, and this runs on the failure path where
    // losing the reason would be worst: recover the guard instead of panicking.
    let mut guard = match tail.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.len() == STDERR_TAIL_LINES {
        guard.pop_front();
    }
    guard.push_back(line);
}

/// Drain QEMU's stderr: every line is logged as it arrives and the last few are kept.
async fn capture_stderr<R>(reader: R, tail: StderrTail)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = strip_ansi_codes(&line).into_owned();
        error!("{line}");
        push_stderr_line(&tail, &line);
    }
}

fn stderr_reason(tail: &StderrTail) -> Option<String> {
    let guard = match tail.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_empty() {
        return None;
    }
    let lines: Vec<&str> = guard.iter().map(String::as_str).collect();
    Some(lines.join(" | "))
}

fn map_qemu_exit_status(
    status: std::process::ExitStatus,
    pid: u32,
    expected_to_exit: &Arc<AtomicBool>,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let expected = expected_to_exit.load(Ordering::SeqCst);
    let detail = describe_exit(&status);
    // Keep the symptom first and the cause second: the status is what the caller can
    // match on, the reason is what tells them which knob to turn.
    let suffix = match reason {
        Some(reason) => format!("QEMU said: {reason}"),
        None => "check its log for the reason".to_string(),
    };

    if status.success() {
        if expected {
            info!("⏏️  Process {} exited as expected", pid);
            return Ok(());
        }
        error!("Process {} exited unexpectedly", pid);
        return Err(anyhow::anyhow!("QEMU exited unexpectedly; {suffix}"));
    }

    // A shutdown was requested: teardown sends SIGTERM and then SIGKILL, so a signal
    // death is the normal outcome of stopping a guest that ignores ACPI powerdown.
    // Reporting it as a launch failure would blame the caller for its own teardown.
    if expected {
        warn!("Process {pid} {detail} while stopping the guest");
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "QEMU {detail} before the VM was asked to stop; {suffix}"
    ))
}

/// Describe how a process died, including the signal name.
///
/// `ExitStatus::code()` is `None` for a signal death, so formatting the code alone
/// produced messages such as "exited with error code: None" that tell the user nothing.
fn describe_exit(status: &std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exited with status {code}");
    }
    match status.signal() {
        Some(signal) => format!("was killed by signal {signal} ({})", signal_name(signal)),
        None => "exited with an unreportable status".to_string(),
    }
}

fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        _ => "unrecognized signal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn firmware(secure_boot: bool) -> VmFirmware {
        VmFirmware {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
            vars: PathBuf::from("/run/qlean/abc/ovmf_vars.fd"),
            secure_boot,
        }
    }

    fn exiting(flag: bool) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(flag))
    }

    fn exit_code(code: i32) -> std::process::ExitStatus {
        std::process::ExitStatus::from_raw(code << 8)
    }

    fn killed_by(signal: i32) -> std::process::ExitStatus {
        std::process::ExitStatus::from_raw(signal)
    }

    /// Give up on a real-QEMU smoke check whose prerequisites this host lacks.
    ///
    /// The check exists to catch an argument contract that only real QEMU can reject
    /// (`swtpm_args` handshake, pflash pair, TPM device), so a missing binary is a skipped
    /// host, not a pass. Everything after the spawn is a hard assertion.
    fn smoke_unavailable(reason: &str) -> bool {
        println!("SMOKE-UNAVAILABLE: {reason}");
        true
    }

    fn program_runs(program: &Path) -> bool {
        std::process::Command::new(program)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Check the QMP control channel against a real QEMU.
    ///
    /// `Machine::shutdown` asks QMP for an ACPI powerdown and every liveness check goes
    /// through `query-status`. Both are built from one chardev string, and the unit tests
    /// only ever talk to a silent fake socket: they can prove a hang is bounded, not that a
    /// real QEMU ever answers. A wrong socket option (`server=on,wait=off`), a missing
    /// capability negotiation or a mis-parsed reply would surface as "every VM is dead" and
    /// "shutdown always falls back to SIGKILL", which is exactly what this checks.
    ///
    /// ```text
    /// cargo test --lib -- --ignored qmp_control_channel
    /// ```
    #[tokio::test]
    #[ignore = "needs qemu-system-x86_64; run with --ignored on a real host"]
    async fn test_the_qmp_control_channel_answers_a_real_qemu() {
        let qemu = Path::new(qemu_system_program(GuestArch::Amd64));
        if !program_runs(qemu) {
            assert!(smoke_unavailable(&format!(
                "`{}` is not runnable",
                qemu.display()
            )));
            return;
        }
        let run_dir = std::env::temp_dir().join(format!("qlean-qmp-real-{}", std::process::id()));
        std::fs::create_dir_all(&run_dir).expect("test run dir");
        let socket = run_dir.join("qmp.sock");
        let _ = std::fs::remove_file(&socket);

        let mut args: Vec<String> = ["-machine", "q35,hpet=off", "-m", "512", "-display", "none"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        args.extend(qmp_chardev_args(&socket).expect("qmp args"));
        let mut child = tokio::process::Command::new(qemu)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn qemu");

        // A VM with no bootable medium still has to report `running`: that is the state
        // `Machine::is_running` treats as alive, and a client that always answered `false`
        // would pass every fake-socket test while declaring live VMs dead.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut running = false;
        let mut last = String::new();
        while std::time::Instant::now() < deadline {
            match crate::qmp::query_running(&socket).await {
                Ok(true) => {
                    running = true;
                    break;
                }
                Ok(false) => last = "query-status reported a stopped VM".to_string(),
                Err(error) => last = format!("{error:#}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            running,
            "QMP never reported the VM as running: {last} (qemu still up: {})",
            child.try_wait().expect("qemu state").is_none()
        );

        crate::qmp::powerdown(&socket)
            .await
            .expect("real QEMU must accept system_powerdown");

        let _ = child.start_kill();
        let _ = child.wait().await;
        // The socket outlives QEMU for a moment; the client must report the path instead of
        // pretending the VM is alive, which is what makes a stopped VM look running.
        let stale = crate::qmp::query_running(&socket).await;
        assert!(
            stale.is_err(),
            "a socket with no QEMU behind it must not answer: {stale:?}"
        );
        let _ = std::fs::remove_dir_all(&run_dir);
    }

    /// Check that real QEMU accepts the Windows firmware/TPM argument list.
    ///
    /// Every other firmware test compares strings: nothing proved that
    /// `swtpm_args` (`not-need-init,startup-clear`, owner-only control socket) really
    /// completes QEMU's TPM handshake, that the copied vars image is accepted as pflash
    /// unit=1, or that the option strings are spelled the way this QEMU wants. Those are
    /// the failures that cannot be seen without the tools, and they are cheap to catch:
    /// the VM is started with `-S`, so no guest code runs and no Windows image is needed.
    ///
    /// Run it where `qemu-system-x86_64`, `swtpm` and the distro OVMF package are installed:
    ///
    /// ```text
    /// cargo test --lib -- --ignored qemu_firmware_contract
    /// ```
    #[tokio::test]
    #[ignore = "needs qemu-system-x86_64 + swtpm + OVMF; run with --ignored on a real host"]
    async fn test_windows_firmware_arguments_are_accepted_by_real_qemu() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let qemu = Path::new(qemu_system_program(GuestArch::Amd64));
        if !program_runs(qemu) {
            assert!(smoke_unavailable(&format!(
                "`{}` is not runnable",
                qemu.display()
            )));
            return;
        }
        let Ok(resolved) = crate::firmware::resolve_ovmf() else {
            assert!(smoke_unavailable("no OVMF firmware pair on this host"));
            return;
        };
        let run_dir = std::env::temp_dir().join(format!("qlean-qemu-fw-{}", std::process::id()));
        std::fs::create_dir_all(&run_dir).expect("test run dir");
        let vars = crate::firmware::prepare_vars(&run_dir, &resolved).expect("vars image");
        let mut tpm = match crate::firmware::Swtpm::start(&run_dir).await {
            Ok(tpm) => tpm,
            Err(error) => {
                assert!(smoke_unavailable(&format!(
                    "`swtpm` did not start: {error}"
                )));
                let _ = std::fs::remove_dir_all(&run_dir);
                return;
            }
        };

        let firmware = VmFirmware {
            code: resolved.code.clone(),
            vars: vars.clone(),
            secure_boot: resolved.secure_boot,
        };
        let mut args = windows_firmware_args(&firmware, Some(tpm.socket())).expect("firmware args");
        for extra in ["-m", "512", "-display", "none", "-S", "-qmp", "stdio"] {
            args.push(extra.to_string());
        }
        let mut child = tokio::process::Command::new(qemu)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn qemu");
        let mut stdout = child.stdout.take().expect("qemu stdout");
        let mut stderr = child.stderr.take().expect("qemu stderr");
        let mut qmp_stdin = child.stdin.take().expect("qemu stdin");

        // The QMP greeting is emitted once the machine, both pflash units and the TPM
        // device have been realized, so a rejected option never reaches it.
        let mut greeting = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(20), stdout.read(&mut byte))
                .await
                .expect("QEMU must emit the QMP greeting within 20s")
                .expect("read qemu stdout");
            if read == 0 {
                break;
            }
            greeting.push(byte[0]);
            if greeting.ends_with(b"\n") && greeting.windows(4).any(|w| w == b"QMP\"") {
                break;
            }
        }
        let greeting = String::from_utf8_lossy(&greeting).to_string();
        assert!(
            greeting.contains("\"QMP\""),
            "QEMU started without a QMP greeting: {greeting}"
        );

        // Ask QEMU what it realized. A `-device`/`-tpmdev` line that was dropped or spelled
        // for another QEMU version still yields a running VM and a greeting, so the device
        // list is what proves the TPM the guest will see is the one this code intends.
        qmp_stdin
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\n{\"execute\":\"query-tpm\"}\n")
            .await
            .expect("write qmp commands");
        let mut replies = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(Ok(read)) =
            tokio::time::timeout(Duration::from_millis(300), stdout.read(&mut chunk)).await
        {
            if read == 0 {
                break;
            }
            replies.extend_from_slice(&chunk[..read]);
        }
        let replies = String::from_utf8_lossy(&replies).to_string();
        assert!(
            replies.contains("\"model\": \"tpm-tis\"") && replies.contains("\"chrtpm\""),
            "QEMU did not realize the configured TPM 2.0 device: {replies}"
        );

        // A TPM that fails its handshake is not fatal to QEMU: it logs and boots the guest
        // without one, which on Windows means a machine Windows 11 will not install on. So
        // the absence of that log line is the real assertion, not a successful spawn.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let mut issues = Vec::new();
        let mut buffer = [0u8; 4096];
        while let Ok(Ok(read)) =
            tokio::time::timeout(Duration::from_millis(200), stderr.read(&mut buffer)).await
        {
            if read == 0 {
                break;
            }
            issues.extend_from_slice(&buffer[..read]);
        }
        let issues = String::from_utf8_lossy(&issues).to_string();
        assert!(
            child.try_wait().expect("qemu state").is_none(),
            "QEMU exited with the Windows argument list: {issues}"
        );
        assert!(
            !issues.contains("tpm-emulator"),
            "the TPM handshake failed even though QEMU kept running: {issues}"
        );
        println!(
            "real QEMU accepted the Windows argument list: firmware={} secure_boot={} vars={}",
            resolved.code.display(),
            resolved.secure_boot,
            vars.display()
        );

        let _ = child.start_kill();
        let _ = child.wait().await;
        tpm.stop().await;
        let _ = std::fs::remove_dir_all(&run_dir);
    }

    /// Check that the guest NIC really carries the MAC Qlean searches DHCP leases for.
    ///
    /// Windows discovery has no other handle on the guest: `find_lease_address` looks the
    /// machine's MAC up in the network's lease table, and every later step (transport, ip,
    /// files) hangs off that lease. A NIC whose `mac=` was dropped, mis-spelled or attached
    /// to a different netdev still boots and still shows up on the bridge, so only the
    /// monitor's own view of the device distinguishes the two.
    #[tokio::test]
    #[ignore = "needs qemu-system-x86_64 and a usable qlbr0 bridge"]
    async fn test_the_guest_nic_carries_the_mac_that_lease_lookup_searches_for() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let qemu = Path::new(qemu_system_program(GuestArch::Amd64));
        if !program_runs(qemu) {
            assert!(smoke_unavailable(&format!(
                "`{}` is not runnable",
                qemu.display()
            )));
            return;
        }
        let mac = crate::utils::gen_random_mac();
        let mut child = tokio::process::Command::new(qemu)
            .args([
                "-netdev",
                &netdev_option(),
                "-device",
                &nic_device_option(&mac),
                "-m",
                "256",
                "-display",
                "none",
                "-S",
                "-qmp",
                "stdio",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn qemu");
        let mut stdout = child.stdout.take().expect("qemu stdout");
        let mut stderr = child.stderr.take().expect("qemu stderr");
        let mut qmp_stdin = child.stdin.take().expect("qemu stdin");

        let mut greeting = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(20), stdout.read(&mut byte))
                .await
                .expect("QEMU must emit the QMP greeting within 20s")
                .expect("read qemu stdout");
            if read == 0 {
                break;
            }
            greeting.push(byte[0]);
            if greeting.ends_with(b"\n") && greeting.windows(4).any(|w| w == b"QMP\"") {
                break;
            }
        }
        let greeting = String::from_utf8_lossy(&greeting).to_string();
        if !greeting.contains("\"QMP\"") {
            // No bridge, no ACL entry for it, or no bridge helper: the argument list is not
            // what failed, so this host cannot answer the question.
            let mut issues = Vec::new();
            let mut buffer = [0u8; 4096];
            while let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(200), stderr.read(&mut buffer)).await
            {
                if read == 0 {
                    break;
                }
                issues.extend_from_slice(&buffer[..read]);
            }
            assert!(smoke_unavailable(&format!(
                "QEMU could not attach to `{}`: {}",
                QLEAN_BRIDGE_NAME,
                String::from_utf8_lossy(&issues).trim()
            )));
            return;
        }

        qmp_stdin
            .write_all(
                b"{\"execute\":\"qmp_capabilities\"}\n{\"execute\":\"human-monitor-command\",\
                  \"arguments\":{\"command-line\":\"info network\"}}\n",
            )
            .await
            .expect("write qmp commands");
        let mut replies = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(Ok(read)) =
            tokio::time::timeout(Duration::from_millis(300), stdout.read(&mut chunk)).await
        {
            if read == 0 {
                break;
            }
            replies.extend_from_slice(&chunk[..read]);
        }
        let replies = String::from_utf8_lossy(&replies).to_string();
        // The monitor prints the device and the backend separately: the NIC line carries
        // `macaddr=`, the backend line carries `net0: … br=`.
        assert!(
            replies.contains(&format!("macaddr={mac}")),
            "the guest NIC does not carry the MAC that lease lookup searches for ({mac}): {replies}"
        );
        assert!(
            replies.contains("net0: index=0,type=tap")
                && replies.contains(&format!("br={QLEAN_BRIDGE_NAME}")),
            "the NIC is not attached to the bridge Qlean reads leases from: {replies}"
        );
        println!("real QEMU reports net0 with the searched-for MAC {mac} on {QLEAN_BRIDGE_NAME}");

        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    /// Build the smoke seed ISO the Windows first boot reads, or `None` when `xorriso` is
    /// not runnable on this host.
    async fn build_a_smoke_seed_iso(run_dir: &Path) -> Option<PathBuf> {
        if !program_runs(Path::new(crate::firmware::SEED_ISO_BUILDER)) {
            return None;
        }
        std::fs::create_dir_all(run_dir.join("seed")).expect("test run dir");
        std::fs::write(
            run_dir.join("seed").join("deploy.json"),
            b"{\"marker\":1}\n",
        )
        .expect("seed payload");
        let iso = run_dir.join("seed.iso");
        let mut iso_cmd = tokio::process::Command::new(crate::firmware::SEED_ISO_BUILDER);
        iso_cmd
            .arg("-as")
            .arg("mkisofs")
            .arg("-V")
            .arg(crate::windows::SEED_VOLUME_LABEL)
            .arg("-J")
            .arg("-R")
            .arg("-o")
            .arg(&iso)
            .arg("-graft-points")
            .arg(format!("qlean={}", run_dir.join("seed").display()));
        crate::utils::run_bounded(
            iso_cmd,
            Duration::from_secs(120),
            "build the smoke seed ISO",
        )
        .await
        .expect("seed ISO built");
        assert!(iso.is_file(), "xorriso did not produce {}", iso.display());
        Some(iso)
    }

    ///
    /// The deployment depends on the guest finding the seed ISO on a bus its early boot
    /// scans. QEMU accepts almost any `-drive` line, so a device that ends up unattached,
    /// on a bus the firmware never probes, or not read-only still yields a running VM and a
    /// 900s wait for a marker the guest could never write. `query-block` is the only thing
    /// that distinguishes "the argument was accepted" from "the guest has this CD-ROM".
    #[tokio::test]
    #[ignore = "needs qemu-system-x86_64 and xorriso on the host"]
    async fn test_the_seed_medium_really_is_an_ide_cdrom() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let qemu = Path::new(qemu_system_program(GuestArch::Amd64));
        if !program_runs(qemu) {
            assert!(smoke_unavailable(&format!(
                "`{}` is not runnable",
                qemu.display()
            )));
            return;
        }
        if !program_runs(Path::new(crate::firmware::SEED_ISO_BUILDER)) {
            assert!(smoke_unavailable("`xorriso` is not runnable"));
            return;
        }

        let run_dir = std::env::temp_dir().join(format!("qlean-qemu-seed-{}", std::process::id()));
        let iso = build_a_smoke_seed_iso(&run_dir)
            .await
            .expect("xorriso was checked as runnable above");

        let drive = seed_drive_option(&iso).expect("seed drive argument");
        let mut child = tokio::process::Command::new(qemu)
            .args([
                "-drive", &drive, "-m", "512", "-display", "none", "-S", "-qmp", "stdio",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn qemu");
        let mut stdout = child.stdout.take().expect("qemu stdout");
        let mut qmp_stdin = child.stdin.take().expect("qemu stdin");

        let mut greeting = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(20), stdout.read(&mut byte))
                .await
                .expect("QEMU must emit the QMP greeting within 20s")
                .expect("read qemu stdout");
            if read == 0 {
                break;
            }
            greeting.push(byte[0]);
            if greeting.ends_with(b"\n") && greeting.windows(4).any(|w| w == b"QMP\"") {
                break;
            }
        }
        let greeting = String::from_utf8_lossy(&greeting).to_string();
        assert!(
            greeting.contains("\"QMP\""),
            "QEMU rejected the seed drive argument: {greeting}"
        );

        qmp_stdin
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\n{\"execute\":\"query-block\"}\n")
            .await
            .expect("write qmp commands");
        let mut replies = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(Ok(read)) =
            tokio::time::timeout(Duration::from_millis(300), stdout.read(&mut chunk)).await
        {
            if read == 0 {
                break;
            }
            replies.extend_from_slice(&chunk[..read]);
        }
        let replies = String::from_utf8_lossy(&replies).to_string();
        let iso_name = iso.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            replies.contains("\"device\": \"ide0-cd0\""),
            "the seed medium did not show up as an IDE CD-ROM: {replies}"
        );
        assert!(
            replies.contains(&format!("\"file\": \"{}\"", iso.display())),
            "the IDE CD-ROM is not backed by the seed ISO {}: {replies}",
            iso.display()
        );
        assert!(
            replies.contains("\"ro\": true") && replies.contains("\"tray_open\": false"),
            "the seed medium must be inserted read-only: {replies}"
        );
        println!(
            "real QEMU realized the seed medium as ide0-cd0 from {iso_name} (read-only, tray closed)"
        );

        let _ = child.start_kill();
        let _ = child.wait().await;
        let _ = std::fs::remove_dir_all(&run_dir);
    }

    /// Talk to a QMP socket without the typed client, so the raw reply can be asserted on.
    ///
    /// Returns every reply line after capability negotiation; the caller looks for the
    /// fields it cares about instead of decoding the whole schema.
    async fn qmp_reply_text(socket: &Path, commands: &[&str]) -> String {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .expect("connect to the QMP socket");
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();
        let greeting = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("QMP must greet within 10s")
            .expect("read the greeting")
            .expect("greeting line");
        assert!(greeting.contains("\"QMP\""), "{greeting}");

        write_half
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
            .await
            .expect("write the capability negotiation");
        for command in commands {
            write_half
                .write_all(format!("{command}\n").as_bytes())
                .await
                .expect("write a QMP command");
        }
        let mut replies = String::new();
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(Duration::from_millis(500), lines.next_line()).await
        {
            replies.push_str(&line);
            replies.push('\n');
        }
        replies
    }

    /// Ask a real QEMU to realize the *whole* Windows launch argument list.
    ///
    /// Every piece of that list has a real-tool test of its own (firmware plus TPM, seed
    /// medium, NIC), and each of them starts QEMU on its own small command line. Nothing ran
    /// the argument list Qlean actually launches: the machine type, two pflash units, the
    /// TPM, the virtio system disk, the stdio multiplexed serial console and the IDE seed
    /// medium all at once. Those pieces compete for the same buses, units and chardev ids, so
    /// a unit that collides, a `-drive` that lands on another bus, or a device the production
    /// machine type does not have still yields a booting QEMU and an answered QMP greeting.
    /// `query-block` is what tells the difference: a guest that boots without its seed medium
    /// spends the whole deployment budget waiting for a marker nobody can write.
    ///
    /// The VM has no bootable medium, so it reaches the firmware's own "no bootable device"
    /// screen and needs no Windows image; the QMP socket answering `running` is the same
    /// state `Machine::is_running` waits for in production.
    /// ```text
    /// cargo test --lib -- --ignored test_the_windows_launch_argument_list_is_realized
    /// ```
    #[tokio::test]
    #[ignore = "needs qemu-system-x86_64 + swtpm + OVMF + xorriso; run with --ignored on a real host"]
    async fn test_the_windows_launch_argument_list_is_realized_by_a_real_qemu() {
        let qemu = Path::new(qemu_system_program(GuestArch::Amd64));
        if !program_runs(qemu) {
            assert!(smoke_unavailable(&format!(
                "`{}` is not runnable",
                qemu.display()
            )));
            return;
        }
        let Ok(resolved) = crate::firmware::resolve_ovmf() else {
            assert!(smoke_unavailable("no OVMF firmware pair on this host"));
            return;
        };

        let run_dir =
            std::env::temp_dir().join(format!("qlean-qemu-launch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run_dir);
        std::fs::create_dir_all(&run_dir).expect("test run dir");
        let Some(iso) = build_a_smoke_seed_iso(&run_dir).await else {
            assert!(smoke_unavailable("`xorriso` is not runnable"));
            let _ = std::fs::remove_dir_all(&run_dir);
            return;
        };
        let vars = crate::firmware::prepare_vars(&run_dir, &resolved).expect("vars image");
        let mut tpm = match crate::firmware::Swtpm::start(&run_dir).await {
            Ok(tpm) => tpm,
            Err(error) => {
                assert!(smoke_unavailable(&format!(
                    "`swtpm` did not start: {error}"
                )));
                let _ = std::fs::remove_dir_all(&run_dir);
                return;
            }
        };

        // A real qcow2 overlay, exactly as `Machine::new` leaves behind: production never
        // boots a raw file, and an unspecified format would add a probe warning that the
        // real launch never prints.
        let overlay = run_dir.join("overlay.img");
        let mut qemu_img = tokio::process::Command::new("qemu-img");
        qemu_img
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg(&overlay)
            .arg("1G");
        crate::utils::run_bounded(
            qemu_img,
            Duration::from_secs(120),
            "create the smoke overlay",
        )
        .await
        .expect("qemu-img created the overlay");

        let socket = run_dir.join("qmp.sock");
        let _ = std::fs::remove_file(&socket);
        let firmware = VmFirmware {
            code: resolved.code.clone(),
            vars: vars.clone(),
            secure_boot: resolved.secure_boot,
        };

        // Exactly what `launch_qemu` builds for a Windows first boot. The NIC is left out:
        // attaching it needs the bridge helper and a bridge, which its own real-QEMU test
        // already requires, and it competes for no unit with anything below.
        let mut args = windows_firmware_args(&firmware, Some(tpm.socket())).expect("firmware args");
        args.extend(qmp_chardev_args(&socket).expect("qmp args"));
        args.push("-drive".to_string());
        args.push(disk_drive_option(&overlay).expect("disk drive argument"));
        args.push("-nographic".to_string());
        args.push("-chardev".to_string());
        args.push(serial_chardev_option(&run_dir.join("serial.log")).expect("serial chardev"));
        for extra in [
            "-serial",
            "chardev:char0",
            "-mon",
            "chardev=char0,mode=readline",
        ] {
            args.push(extra.to_string());
        }
        args.push("-drive".to_string());
        args.push(seed_drive_option(&iso).expect("seed drive argument"));
        for extra in ["-m", "512", "-smp", "2"] {
            args.push(extra.to_string());
        }

        let mut child = tokio::process::Command::new(qemu)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn qemu");
        let mut stderr = child.stderr.take().expect("qemu stderr");

        // The production control channel is the QMP socket, so the launch is only accepted
        // when that socket answers. A rejected option exits QEMU before the socket exists.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut running = false;
        let mut last = String::new();
        while std::time::Instant::now() < deadline {
            if child.try_wait().expect("qemu state").is_some() {
                break;
            }
            match crate::qmp::query_running(&socket).await {
                Ok(true) => {
                    running = true;
                    break;
                }
                Ok(false) => last = "query-status reported a stopped VM".to_string(),
                Err(error) => last = format!("{error:#}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let mut issues = Vec::new();
        let mut buffer = [0u8; 4096];
        let block = if running {
            qmp_reply_text(&socket, &["{\"execute\":\"query-block\"}"]).await
        } else {
            issues.push(format!(
                "the control channel never reported a running VM: {last}"
            ));
            String::new()
        };
        {
            use tokio::io::AsyncReadExt;
            while let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_millis(200), stderr.read(&mut buffer)).await
            {
                if read == 0 {
                    break;
                }
                issues.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            }
        }
        let issues = issues.join("");
        let alive = child.try_wait().expect("qemu state").is_none();

        let _ = child.start_kill();
        let _ = child.wait().await;
        tpm.stop().await;
        let _ = std::fs::remove_dir_all(&run_dir);

        assert!(
            alive && running,
            "real QEMU did not accept the Windows launch argument list: {issues}"
        );
        assert!(
            !issues.contains("tpm-emulator"),
            "the TPM handshake failed even though QEMU kept running: {issues}"
        );

        // pflash0 is the read-only code image and pflash1 the per-VM vars template: the pair
        // the guest boots from has to be the pair Qlean copied, not two devices that happen to
        // be named alike.
        assert!(
            block.contains("\"device\": \"pflash0\"")
                && block.contains(&format!("\"file\": \"{}\"", resolved.code.display())),
            "the firmware code image did not end up in the read-only pflash unit: {block}"
        );
        assert!(
            block.contains("\"device\": \"pflash1\"")
                && block.contains(&format!("\"file\": \"{}\"", vars.display())),
            "the per-VM vars image did not end up in the writable pflash unit: {block}"
        );
        // The system disk competes with the pflash units for the machine's devices; a disk that
        // landed on another bus still runs the guest, just not the one Qlean configured.
        assert!(
            block.contains("\"device\": \"virtio0\"")
                && block.contains(&format!("\"file\": \"{}\"", overlay.display())),
            "the disk overlay is not the guest's virtio system disk: {block}"
        );
        // The deployment depends on this one: the seed medium has to be the read-only CD-ROM
        // the firmware's early boot scans, next to the TPM and the two pflash units.
        assert!(
            block.contains("\"device\": \"ide0-cd0\"")
                && block.contains(&format!("\"file\": \"{}\"", iso.display())),
            "the seed medium is not the guest's IDE CD-ROM: {block}"
        );
        assert!(
            block.contains("\"tray_open\": false"),
            "the seed medium is not inserted: {block}"
        );
        println!(
            "real QEMU realized the whole Windows launch argument list: {}",
            args.join(" ")
        );
    }

    #[test]
    fn test_a_killed_guest_is_not_a_launch_failure_during_teardown() {
        // Tearing a Windows guest down escalates to SIGTERM/SIGKILL when the guest ignores
        // ACPI powerdown, so this must not be reported as "QEMU exited with error code".
        assert!(
            map_qemu_exit_status(killed_by(15), 42, &exiting(true), None).is_ok(),
            "SIGTERM during the requested shutdown is the normal outcome"
        );
        assert!(map_qemu_exit_status(killed_by(9), 42, &exiting(true), None).is_ok());
        assert!(map_qemu_exit_status(exit_code(1), 42, &exiting(true), None).is_ok());
    }

    #[test]
    fn test_an_unexpected_death_reports_the_signal_instead_of_none() {
        let error = map_qemu_exit_status(killed_by(9), 42, &exiting(false), None)
            .expect_err("a guest that was never asked to stop must not die silently")
            .to_string();
        assert!(error.contains("signal 9"), "{error}");
        assert!(error.contains("SIGKILL"), "{error}");
        // `ExitStatus::code()` is None for a signal death; the old message said "None".
        assert!(!error.contains("None"), "{error}");
    }

    #[test]
    fn test_an_unexpected_exit_status_is_named() {
        let clean = map_qemu_exit_status(exit_code(0), 42, &exiting(false), None)
            .expect_err("exit without a request is still a failure")
            .to_string();
        assert!(clean.contains("exited unexpectedly"), "{clean}");

        let failed = map_qemu_exit_status(exit_code(3), 42, &exiting(false), None)
            .expect_err("a non-zero status is a failure")
            .to_string();
        assert!(failed.contains("status 3"), "{failed}");
        assert!(!failed.contains("None"), "{failed}");
    }

    #[test]
    fn test_an_expected_exit_is_not_an_error() {
        assert!(map_qemu_exit_status(exit_code(0), 42, &exiting(true), None).is_ok());
    }

    /// A launch failure must return the cause QEMU printed, not only its exit status.
    ///
    /// QEMU explains every refusal on stderr (`Could not open '/dev/kvm'`, `UNIX socket
    /// path ... is too long`). Reporting `exited with status 1; check its log` threw that
    /// away: on a Windows guest the caller had already spent the deployment budget and
    /// the actionable sentence sat in a log file instead of in the error.
    #[tokio::test]
    async fn test_a_launch_failure_returns_the_reason_the_process_printed() {
        // A real process, because the claim is about the pipe between the reader task and
        // the error: a hand-built string would prove nothing about that wiring.
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(
                "echo \"qemu-system-x86_64: Could not open '/dev/kvm': Permission denied\" >&2; \
                 echo 'qemu-system-x86_64: failed to initialize kvm' >&2; exit 9",
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the stand-in process");

        let stderr = child.stderr.take().expect("stderr pipe");
        let tail = new_stderr_tail();
        capture_stderr(stderr, Arc::clone(&tail)).await;
        let status = child.wait().await.expect("wait for the stand-in process");

        let reason = stderr_reason(&tail).expect("the process's own words must be kept");
        assert!(reason.contains("/dev/kvm"), "{reason}");

        let error = qemu_exit_result(Ok(status), 42, &exiting(false), &tail)
            .expect_err("an unexpected death is a failure")
            .to_string();
        assert!(error.contains("status 9"), "{error}");
        assert!(
            error.contains("/dev/kvm"),
            "the cause must travel with the symptom: {error}"
        );
        assert!(
            !error.contains("check its log"),
            "a known reason must not be replaced by a pointer to the log: {error}"
        );
    }

    #[test]
    fn test_the_stderr_tail_is_bounded_and_still_points_at_the_log_when_empty() {
        let tail = new_stderr_tail();
        for index in 0..(STDERR_TAIL_LINES + 5) {
            push_stderr_line(&tail, &format!("line {index}"));
        }
        let reason = stderr_reason(&tail).expect("kept lines must be reported");
        let kept: Vec<&str> = reason.split(" | ").collect();
        assert_eq!(kept.len(), STDERR_TAIL_LINES, "{reason}");
        assert_eq!(
            kept[0], "line 5",
            "the oldest lines must be dropped: {reason}"
        );
        assert_eq!(
            kept[STDERR_TAIL_LINES - 1],
            format!("line {}", STDERR_TAIL_LINES + 4),
            "the newest line must be last: {reason}"
        );

        // A blank line carries no reason and would only add noise.
        push_stderr_line(&tail, "   ");
        assert_eq!(
            stderr_reason(&tail).unwrap().split(" | ").count(),
            STDERR_TAIL_LINES
        );

        // One enormous line (QEMU echoes whole command lines) must not flood the error.
        let long = "x".repeat(STDERR_TAIL_WIDTH + 100);
        let long_tail = new_stderr_tail();
        push_stderr_line(&long_tail, &long);
        let kept = stderr_reason(&long_tail).unwrap();
        assert!(kept.ends_with('…'), "a long line must be truncated: {kept}");
        assert_eq!(kept.chars().count(), STDERR_TAIL_WIDTH + 1);

        // With nothing captured the message still has to say something useful.
        let bare = qemu_exit_result(Ok(exit_code(1)), 42, &exiting(false), &new_stderr_tail())
            .expect_err("a non-zero status is a failure")
            .to_string();
        assert!(bare.contains("check its log"), "{bare}");
    }

    #[test]
    fn test_windows_firmware_args_with_secure_boot_and_tpm() {
        let args = windows_firmware_args(
            &firmware(true),
            Some(Path::new("/run/qlean/abc/swtpm.sock")),
        )
        .unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("-machine q35,hpet=off,smm=on"), "{joined}");
        assert!(
            joined.contains("driver=cfi.pflash01,property=secure,value=on"),
            "{joined}"
        );
        assert!(
            joined.contains(
                "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("if=pflash,format=raw,unit=1,file=/run/qlean/abc/ovmf_vars.fd"),
            "{joined}"
        );
        // The vars image must never be read-only: it carries per-VM boot state.
        assert!(!joined.contains("unit=1,readonly=on"), "{joined}");
        assert!(
            joined.contains("-tpmdev emulator,id=tpm0,chardev=chrtpm"),
            "{joined}"
        );
        assert!(joined.contains("-device tpm-tis,tpmdev=tpm0"), "{joined}");
    }

    #[test]
    fn test_windows_firmware_args_reject_paths_that_break_the_option_encoding() {
        // A comma in the file name would be parsed as another key=value pair, so the
        // value must be rejected before QEMU ever sees it.
        let mut comma_code = firmware(true);
        comma_code.code = PathBuf::from("/run/qlean,a/OVMF_CODE.fd");
        let error = windows_firmware_args(&comma_code, None)
            .expect_err("a comma in the OVMF code path must be refused")
            .to_string();
        assert!(error.contains("OVMF code image"), "{error}");
        assert!(error.contains("comma"), "{error}");

        let mut comma_vars = firmware(true);
        comma_vars.vars = PathBuf::from("/run/qlean/abc,unsafe/ovmf_vars.fd");
        let error = windows_firmware_args(&comma_vars, None)
            .expect_err("a comma in the OVMF vars path must be refused")
            .to_string();
        assert!(error.contains("OVMF vars image"), "{error}");

        let error =
            windows_firmware_args(&firmware(true), Some(Path::new("/run/q,lean/swtpm.sock")))
                .expect_err("a comma in the swtpm socket path must be refused")
                .to_string();
        assert!(error.contains("swtpm control socket"), "{error}");

        // Spaces are legitimate: the value travels as one argv element.
        let mut spaced = firmware(true);
        spaced.code = PathBuf::from("/run/qlean dir/OVMF_CODE.fd");
        let args = windows_firmware_args(&spaced, None).unwrap();
        assert!(
            args.iter()
                .any(|a| a.ends_with("file=/run/qlean dir/OVMF_CODE.fd")),
            "{args:?}"
        );
    }

    #[test]
    fn test_windows_guest_gets_no_vsock_device() {
        assert!(
            vsock_args(GuestOs::Windows, 42).is_empty(),
            "Windows guests have no vsock driver and must not require /dev/vhost-vsock"
        );
    }

    #[test]
    fn test_linux_guest_keeps_the_vsock_device() {
        let args = vsock_args(GuestOs::Linux, 42);
        assert_eq!(args[0], "-device");
        assert!(
            args[1].starts_with("vhost-vsock-pci,") && args[1].contains("guest-cid=42"),
            "{args:?}"
        );
    }

    #[test]
    fn test_windows_firmware_args_without_secure_boot() {
        let args = windows_firmware_args(&firmware(false), None).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("-machine q35,hpet=off"), "{joined}");
        assert!(!joined.contains("smm=on"), "{joined}");
        assert!(!joined.contains("cfi.pflash01"), "{joined}");
        // No TPM socket means no TPM device at all; never half-configured.
        assert!(!joined.contains("tpm"), "{joined}");
        assert!(joined.contains("if=pflash"), "{joined}");
    }

    #[test]
    fn test_select_accel_prefers_kvm() {
        assert_eq!(
            select_accel(true, true, GuestOs::Linux).unwrap(),
            Accel::Kvm
        );
        assert_eq!(
            select_accel(true, true, GuestOs::Windows).unwrap(),
            Accel::Kvm
        );
    }

    #[test]
    fn test_select_accel_keeps_tcg_for_linux_only() {
        assert_eq!(
            select_accel(false, true, GuestOs::Linux).unwrap(),
            Accel::Tcg
        );
        assert_eq!(
            select_accel(true, false, GuestOs::Linux).unwrap(),
            Accel::Tcg
        );
    }

    #[test]
    fn test_select_accel_never_falls_back_to_tcg_for_windows() {
        for (kvm, host_matches) in [(false, true), (true, false), (false, false)] {
            let err = select_accel(kvm, host_matches, GuestOs::Windows)
                .unwrap_err()
                .to_string();
            assert!(err.contains("TCG"), "{err}");
            assert!(err.contains("KVM"), "{err}");
        }
    }
}
