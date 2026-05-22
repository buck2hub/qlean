use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use console::strip_ansi_codes;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::{
    MachineConfig,
    image::GuestArch,
    is_kvm_available,
    machine::MachineImage,
    utils::{CommandExt, QLEAN_BRIDGE_NAME, QleanDirs},
};

const QEMU_TIMEOUT: Duration = Duration::from_secs(360 * 60); // 6 hours

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
}

pub(crate) async fn launch_qemu(params: QemuLaunchParams) -> anyhow::Result<()> {
    // Prepare QEMU command
    let mut qemu_cmd = tokio::process::Command::new(qemu_system_program(params.image.arch));
    if params.image.arch == GuestArch::Amd64 {
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

    if is_kvm_available() && host_arch() == Some(params.image.arch) {
        // KVM acceleration
        qemu_cmd.args(["-accel", "kvm"]).args(["-cpu", "host"]);
    } else {
        qemu_cmd.args(["-accel", "tcg"]);
        warn!(
            "KVM acceleration is unavailable for this host/guest architecture pair. Falling back to TCG emulation, which may be slower."
        );
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

    let result = match timeout(QEMU_TIMEOUT, qemu_child.wait()).await {
        Err(_) => {
            error!("QEMU process timed out after 6 hours");
            Err(anyhow::anyhow!("QEMU process timed out"))
        }
        Ok(Err(e)) => {
            error!("Failed to wait for QEMU: {}", e);
            Err(e.into())
        }
        Ok(Ok(status)) => {
            if status.success() {
                if params.expected_to_exit.load(Ordering::SeqCst) {
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
    };

    // Cancel any ongoing operations due to QEMU exit
    params.cancel_token.cancel();

    // Wait for logging tasks to complete
    let _ = tokio::join!(stdout_task, stderr_task);

    result
}
