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
    KVM_AVAILABLE, MachineConfig,
    machine::MachineImage,
    utils::{
        CommandExt, QLEAN_BRIDGE_NAME, QleanDirs, bridge_conf_allows, has_iface, has_vsock_support,
    },
};

const QEMU_TIMEOUT: Duration = Duration::from_secs(360 * 60); // 6 hours

pub struct QemuLaunchParams {
    pub expected_to_exit: Arc<AtomicBool>,
    pub cid: u32,
    pub image: MachineImage,
    pub config: MachineConfig,
    pub vmid: String,
    pub is_init: bool,
    pub cancel_token: CancellationToken,
    pub mac_address: String,
}

pub async fn launch_qemu(params: QemuLaunchParams) -> anyhow::Result<()> {
    // Prepare QEMU command
    let mut qemu_cmd = tokio::process::Command::new("qemu-system-x86_64");

    qemu_cmd
        // Decrease idle CPU usage
        .args(["-machine", "hpet=off"]);

    // Qlean's SSH transport is vhost-vsock. Without it we cannot reach the guest.
    anyhow::ensure!(
        has_vsock_support(),
        "Missing /dev/vhost-vsock; vhost-vsock is required (no TCP fallback)."
    );
    qemu_cmd.args([
        "-device",
        &format!(
            "vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={}",
            params.cid
        ),
    ]);

    let use_direct_kernel_boot = params.image.prefer_direct_kernel_boot
        && params.image.kernel.exists()
        && params.image.initrd.exists()
        && std::fs::metadata(&params.image.kernel)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        && std::fs::metadata(&params.image.initrd)
            .map(|m| m.len() > 0)
            .unwrap_or(false);

    anyhow::ensure!(
        use_direct_kernel_boot,
        "Kernel/initrd extraction is required before QEMU launch."
    );

    // Qlean configures an SSH endpoint over vsock through cloud-init. The guest listens on
    // vsock port 22 and proxies to its regular TCP sshd listener.
    //
    // For Fedora/Arch images, a minimal "root=/dev/vdaX" command line is often insufficient.
    // Cloud images may rely on BLS/GRUB kernelopts (UUID/rootflags/btrfs subvols, etc.).
    // We therefore pass through the full kernel args extracted from /boot when available.
    let mut tokens = params.image.root_arg.split_whitespace().collect::<Vec<_>>();
    if !tokens.iter().any(|t| *t == "rw" || *t == "ro") {
        tokens.push("rw");
    }
    // Force NoCloud datasource for cloud-init so guests don't spend time probing
    // metadata services that are unavailable in this test environment.
    if !tokens.iter().any(|t| t.starts_with("ds=")) {
        tokens.push("ds=nocloud");
    }
    if !tokens.iter().any(|t| t.starts_with("console=")) {
        tokens.push("console=ttyS0,115200n8");
    }
    let kernel_cmdline = tokens.join(" ");

    qemu_cmd
        .args(["-kernel", params.image.kernel.to_str().unwrap()])
        .args(["-append", &kernel_cmdline])
        .args(["-initrd", params.image.initrd.to_str().unwrap()]);

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

    // ---------------------------------------------------------------------
    // Network
    // Qlean requires the libvirt-managed bridge.
    // ---------------------------------------------------------------------
    let want_bridge = has_iface(QLEAN_BRIDGE_NAME) && bridge_conf_allows(QLEAN_BRIDGE_NAME);

    anyhow::ensure!(
        want_bridge,
        "QEMU bridge helper is not configured to allow '{}'. Hint: add `allow {}` (or `allow all`) to /etc/qemu/bridge.conf.",
        QLEAN_BRIDGE_NAME,
        QLEAN_BRIDGE_NAME
    );

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
    let dirs = QleanDirs::new()?;
    let run_dir = dirs.runs.join(&params.vmid);
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
    if params.is_init {
        // Seed ISO
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

    let kvm_available = KVM_AVAILABLE.get().copied().unwrap_or(false);
    if kvm_available {
        // KVM acceleration
        qemu_cmd.args(["-accel", "kvm"]).args(["-cpu", "host"]);
    } else {
        warn!(
            "KVM is not available on this host. QEMU will run without hardware acceleration, which may result in significantly reduced performance."
        );
    }

    // Spawn QEMU process
    info!("Starting QEMU");
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
            trace!("[qemu] {}", strip_ansi_codes(&line));
        }
    });

    // Capture and log stderr
    let stderr = qemu_child.stderr.take().expect("Failed to capture stderr");
    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            error!("[qemu] {}", strip_ansi_codes(&line));
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
