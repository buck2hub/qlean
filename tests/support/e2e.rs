use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

const QLEAN_BRIDGE_NAME: &str = "qlbr0";

fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

fn ensure_vm_test_commands() -> Result<()> {
    if !has_cmd("virsh") {
        bail!("Missing required command: virsh (libvirt-clients).");
    }
    if !has_cmd("qemu-system-x86_64") && !has_cmd("qemu-kvm") {
        bail!("Missing required command: qemu-system-x86_64 (or qemu-kvm).");
    }
    Ok(())
}

fn ensure_libvirt_system() -> Result<()> {
    let output = Command::new("virsh")
        .args(["-c", "qemu:///system", "list", "--all"])
        .output()
        .context("failed to execute `virsh -c qemu:///system list --all`")?;

    if !output.status.success() {
        bail!(
            "libvirt system URI is not usable: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

fn has_iface(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}")).exists()
}

fn bridge_conf_allows(bridge: &str) -> bool {
    let path = Path::new("/etc/qemu/bridge.conf");
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };

    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|line| line == "allow all" || line == format!("allow {bridge}"))
}

pub fn ensure_vm_test_env() -> Result<()> {
    ensure_vm_test_commands()?;
    ensure_libvirt_system()?;

    if !Path::new("/dev/vhost-vsock").exists() {
        bail!(
            "Missing required device: /dev/vhost-vsock (vhost-vsock is required; no TCP fallback)."
        );
    }

    if !has_iface(QLEAN_BRIDGE_NAME) {
        bail!(
            "Missing required bridge interface '{}'. Hint: ensure the libvirt network 'qlean' is active (virsh -c qemu:///system net-start qlean).",
            QLEAN_BRIDGE_NAME
        );
    }
    if !bridge_conf_allows(QLEAN_BRIDGE_NAME) {
        bail!(
            r#"QEMU bridge helper is not configured to allow '{}'.

Fix (run once as root):
  sudo bash ./scripts/setup-host-prereqs.sh

Or manually:
  sudo mkdir -p /etc/qemu
  echo "allow {}" | sudo tee /etc/qemu/bridge.conf
  sudo chmod 644 /etc/qemu/bridge.conf

Also ensure qemu-bridge-helper has CAP_NET_ADMIN (recommended):
  sudo chmod u-s /usr/lib/qemu/qemu-bridge-helper
  sudo setcap cap_net_admin+ep /usr/lib/qemu/qemu-bridge-helper

Then re-run the test."#,
            QLEAN_BRIDGE_NAME,
            QLEAN_BRIDGE_NAME
        );
    }

    Ok(())
}
