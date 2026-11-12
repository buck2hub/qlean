use std::{
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

fn qemu_system_program(arch: GuestArch) -> &'static str {
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
fn windows_firmware_args(firmware: &VmFirmware, tpm_socket: Option<&Path>) -> Vec<String> {
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
        firmware.code.to_string_lossy()
    ));
    args.push("-drive".to_string());
    args.push(format!(
        "if=pflash,format=raw,unit=1,file={}",
        firmware.vars.to_string_lossy()
    ));
    if let Some(socket) = tpm_socket {
        args.push("-chardev".to_string());
        args.push(format!(
            "socket,id=chrtpm,path={}",
            socket.to_string_lossy()
        ));
        args.push("-tpmdev".to_string());
        args.push("emulator,id=tpm0,chardev=chrtpm".to_string());
        args.push("-device".to_string());
        args.push("tpm-tis,tpmdev=tpm0".to_string());
    }
    args
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
        ));
    } else if params.image.arch == GuestArch::Amd64 {
        // Decrease idle CPU usage on x86_64.
        qemu_cmd.args(["-machine", "hpet=off"]);
    }

    qemu_cmd.args([
        "-device",
        &format!(
            "vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={}",
            params.cid
        ),
    ]);

    let dirs = QleanDirs::new()?;
    let run_dir = dirs.runs.join(&params.vmid);
    let qmp_socket = run_dir.join("qmp.sock");
    if qmp_socket.exists() {
        let _ = std::fs::remove_file(&qmp_socket);
    }

    qemu_cmd.args([
        "-chardev",
        &format!(
            "socket,path={},server=on,wait=off,id=qmp0",
            qmp_socket.to_string_lossy()
        ),
        "-mon",
        "chardev=qmp0,mode=control",
    ]);

    qemu_cmd
        // Disk
        .args([
            "-drive",
            &format!(
                "file={},if=virtio,cache=writeback",
                params.image.overlay.to_str().unwrap()
            ),
        ])
        // No GUI
        .arg("-nographic");

    qemu_cmd
        .args([
            "-netdev",
            &format!("bridge,id=net0,br={}", QLEAN_BRIDGE_NAME),
        ])
        .args([
            "-device",
            &format!("virtio-net-pci,netdev=net0,mac={}", params.mac_address),
        ]);

    // Memory and CPUs
    qemu_cmd
        .args(["-m", &params.config.mem.to_string()])
        .args(["-smp", &params.config.core.to_string()]);

    // Output redirection
    // We multiplex QEMU monitor + guest serial onto stdio AND tee it into a file under the run dir.
    let serial_log = run_dir.join("serial.log");
    qemu_cmd
        .args([
            "-chardev",
            &format!(
                "stdio,id=char0,mux=on,signal=off,logfile={},logappend=on",
                serial_log.to_string_lossy()
            ),
        ])
        .args(["-serial", "chardev:char0"])
        .args(["-mon", "chardev=char0,mode=readline"]);

    // Seed ISO is only used for initial boot with cloud-init.
    if params.is_init {
        qemu_cmd.args([
            "-drive",
            &format!(
                // Use an emulated CD-ROM device for maximum compatibility with NoCloud on Fedora/Arch.
                // Some images do not reliably scan virtio-cdrom paths during early boot.
                "file={},if=ide,media=cdrom,readonly=on",
                params.image.seed.to_str().unwrap()
            ),
        ]);
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

    // Capture and log stderr
    let stderr = qemu_child.stderr.take().expect("Failed to capture stderr");
    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            error!("{}", strip_ansi_codes(&line));
        }
    });

    let result = match resolve_qemu_wait_timeout() {
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
            Ok(Ok(status)) => map_qemu_exit_status(status, pid, &params.expected_to_exit),
        },
        None => match qemu_child.wait().await {
            Err(e) => {
                error!("Failed to wait for QEMU: {}", e);
                Err(e.into())
            }
            Ok(status) => map_qemu_exit_status(status, pid, &params.expected_to_exit),
        },
    };

    // Cancel any ongoing operations due to QEMU exit (or intentional kill after timeout)
    params.cancel_token.cancel();

    // Wait for logging tasks to complete
    let _ = tokio::join!(stdout_task, stderr_task);

    result
}

fn map_qemu_exit_status(
    status: std::process::ExitStatus,
    pid: u32,
    expected_to_exit: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    if status.success() {
        if expected_to_exit.load(Ordering::SeqCst) {
            info!("⏏️  Process {} exited as expected", pid);
            Ok(())
        } else {
            error!("Process {} exited unexpectedly", pid);
            Err(anyhow::anyhow!("QEMU exited unexpectedly"))
        }
    } else {
        Err(anyhow::anyhow!(
            "QEMU exited with error code: {:?}",
            status.code()
        ))
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

    #[test]
    fn test_windows_firmware_args_with_secure_boot_and_tpm() {
        let args = windows_firmware_args(
            &firmware(true),
            Some(Path::new("/run/qlean/abc/swtpm.sock")),
        );
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
    fn test_windows_firmware_args_without_secure_boot() {
        let args = windows_firmware_args(&firmware(false), None);
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
