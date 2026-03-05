use anyhow::{Result, bail};
use std::process::Command;

fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

/// Require the libguestfs command-line tools that the real extraction path uses.
///
/// Qlean relies on the host's libguestfs installation and appliance setup.
/// The tests intentionally do not attempt to provision appliances at runtime.
pub fn ensure_guestfish_tools() -> Result<()> {
    if !has_cmd("guestfish") {
        bail!("Missing required command: guestfish (package: libguestfs-tools).");
    }
    if !has_cmd("virt-copy-out") {
        bail!("Missing required command: virt-copy-out (package: libguestfs-tools).");
    }
    Ok(())
}
