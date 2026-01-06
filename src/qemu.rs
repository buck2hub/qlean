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
use tracing::{debug, error, info, trace};

use crate::{
    MachineConfig,
    machine::MachineImage,
    utils::{CommandExt, QleanDirs},
};

const QEMU_TIMEOUT: Duration = Duration::from_secs(360 * 60); // 6 hours

pub async fn launch_qemu(
    expected_to_exit: Arc<AtomicBool>,
    cid: u32,
    image: MachineImage,
    config: MachineConfig,
    vmid: String,
    is_init: bool,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    // Prepare QEMU command
    let mut qemu_cmd = tokio::process::Command::new("qemu-system-x86_64");
    qemu_cmd
        // Decrease idle CPU usage
        .args(["-machine", "hpet=off"])
        // SSH port forwarding
        .args([
            "-device",
            &format!("vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={cid}"),
        ])
        // Kernel
        .args(["-kernel", image.kernel.to_str().unwrap()])
        .args(["-append", "rw root=/dev/vda1 console=ttyS0"])
        // Initrd
        .args(["-initrd", image.initrd.to_str().unwrap()])
        // Disk
        .args([
            "-drive",
            &format!(
                "file={},if=virtio,cache=writeback",
                image.overlay.to_str().unwrap()
            ),
        ])
        // No GUI
        .arg("-nographic")
        // Network
        .args(["-netdev", "user,id=net0"])
        .args(["-device", "virtio-net-pci,netdev=net0"])
        // Memory and CPUs
        .args(["-m", &config.mem.to_string()])
        .args(["-smp", &config.core.to_string()])
        // KVM acceleration
        .args(["-accel", "kvm"])
        .args(["-cpu", "host"])
        // Output redirection
        .args(["-serial", "mon:stdio"]);

    if is_init {
        // Seed ISO
        qemu_cmd.args([
            "-drive",
            &format!(
                "file={},if=virtio,media=cdrom",
                image.seed.to_str().unwrap()
            ),
        ]);
    }

    // Spawn QEMU process
    debug!("Spawning QEMU with command:\n{:?}", qemu_cmd.to_string());
    let mut qemu_child = qemu_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    // Store QEMU PID
    let pid = qemu_child.id().expect("failed to get QEMU PID");
    let dirs = QleanDirs::new()?;
    let pid_file_path = dirs.runs.join(vmid).join("qemu.pid");
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
    };

    // Cancel any ongoing operations due to QEMU exit
    cancel_token.cancel();

    // Wait for logging tasks to complete
    let _ = tokio::join!(stdout_task, stderr_task);

    result
}
