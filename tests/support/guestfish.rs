use anyhow::{Context, Result, bail};
use std::process::Command;

fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

fn combined_output(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{}\n{}", stdout, stderr),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => "(no output)".to_string(),
    }
}

/// Require the host libguestfs tools/runtime used by the real extraction path.
///
/// Reviewer feedback explicitly asked to fix the host-side libguestfs setup
/// instead of provisioning fallback appliances at runtime, so E2E checks fail
/// fast here if the host installation is incomplete.
pub fn ensure_guestfish_tools() -> Result<()> {
    if !has_cmd("guestfish") {
        bail!("Missing required command: guestfish (package: libguestfs-tools).");
    }
    if !has_cmd("virt-copy-out") {
        bail!("Missing required command: virt-copy-out (package: libguestfs-tools).");
    }
    if !has_cmd("libguestfs-test-tool") {
        bail!("Missing required command: libguestfs-test-tool (package: libguestfs-tools).");
    }

    let output = Command::new("libguestfs-test-tool")
        .env("LIBGUESTFS_BACKEND", "direct")
        .output()
        .with_context(|| "failed to execute `libguestfs-test-tool`")?;

    if !output.status.success() {
        bail!(
            "libguestfs-test-tool failed; fix the host libguestfs-tools installation before running E2E tests:\n{}",
            combined_output(&output)
        );
    }
    Ok(())
}
