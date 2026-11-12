//! Qlean is a system-level isolation testing library built on QEMU/KVM.
//! It spins up lightweight VMs in your Rust tests so privileged or risky operations stay off the host.
//!
//! # Features
//!
//! - **Isolation**: Each test runs in its own VM, so failures don't bring down the host.
//! - **Distributed testing**: Easily create and manage multiple virtual machines from test code.
//! - **RAII-style interface**: Automatic resource management ensures VMs are properly cleaned up.
//! - **Out-of-the-box**: Automated image downloading with verification, no manual configuration needed.
//! - **Linux native**: Native support for Linux hosts with multiple guest distributions and architectures.
//! - **Windows guests** (unreleased, tracked as 0.4.0): `GuestOs::Windows` runs a licensed qcow2 you
//!   supply over OVMF + a per-VM TPM 2.0 and a TCP transport. It needs QEMU, OVMF, `swtpm`,
//!   `xorriso` and libvirt on the host; see the README "Windows image contract" section.
//!
//! # Examples
//!
//! Examples can be found in the [tests](https://github.com/buck2hub/qlean/tree/main/tests) directory.
//!
//! # Getting Started
//!
//! For a quick start, see <https://buck2hub.com/docs/qlean>.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use kvm_ioctls::Kvm;

use crate::utils::{ensure_host_prerequisites, ensure_prerequisites};

mod exec;
mod firmware;
mod guest_path;
mod image;
mod machine;
mod pool;
mod qemu;
mod qmp;
mod ssh;
mod utils;
mod windows;

// Re-export public types and functions
pub use image::Distro;
pub use image::GuestArch;
pub use image::GuestOs;
pub use image::Image;
pub use image::ImageConfig;
pub use machine::{Machine, MachineConfig};
pub use pool::MachinePool;
pub use ssh::{InteractiveShell, InteractiveShellReader, InteractiveShellWriter};

/// Check if KVM is available on the host.
pub fn is_kvm_available() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        return false;
    }

    Kvm::new().is_ok()
}

/// Execute a closure with a virtual machine.
pub async fn with_machine<'a, F, R>(image: &'a Image, config: &'a MachineConfig, f: F) -> Result<R>
where
    F: for<'b> FnOnce(&'b mut Machine) -> Pin<Box<dyn Future<Output = Result<R>> + 'b>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Qlean currently only supports Linux hosts.");
    }

    ensure_prerequisites(image.guest_os()).await?;

    let mut machine = Machine::new(image, config).await?;
    machine.init().await?;
    let outcome = f(&mut machine).await;
    let shutdown = machine.shutdown().await;

    combine_outcome(outcome, shutdown)
}

/// Execute a closure with a virtual machine pool.
pub async fn with_pool<F, R>(f: F) -> Result<R>
where
    F: for<'a> FnOnce(&'a mut MachinePool) -> Pin<Box<dyn Future<Output = Result<R>> + 'a>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Qlean currently only supports Linux hosts.");
    }

    // Pool members may be Windows guests, which do not need vsock; guest-specific
    // requirements are enforced when each machine starts.
    ensure_host_prerequisites().await?;

    let mut pool = MachinePool::new();
    let outcome = f(&mut pool).await;
    let shutdown = pool.shutdown_all().await;

    combine_outcome(outcome, shutdown)
}

/// Report the closure's outcome, keeping a teardown failure as context on it.
///
/// A teardown failure used to replace the closure's error outright: a test that failed for
/// its own reason reported only "cleanup failed", which hides the actual defect and sends
/// the reader after the wrong problem. The closure's error stays the primary one and the
/// teardown error is attached to it; a teardown failure on its own is still an error
/// because a VM that could not be stopped leaks resources.
fn combine_outcome<T>(outcome: Result<T>, shutdown: Result<()>) -> Result<T> {
    match (outcome, shutdown) {
        (Err(error), Err(teardown)) => {
            Err(error.context(format!("teardown also failed: {teardown:#}")))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(teardown)) => Err(teardown),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::combine_outcome;

    #[test]
    fn a_closure_failure_keeps_its_own_cause_when_teardown_fails_too() {
        let error = combine_outcome::<()>(
            Err(anyhow::anyhow!("the guest command failed")),
            Err(anyhow::anyhow!("QEMU did not stop")),
        )
        .expect_err("a failed closure stays a failure");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("the guest command failed"), "{rendered}");
        assert!(rendered.contains("QEMU did not stop"), "{rendered}");
    }

    #[test]
    fn a_successful_closure_does_not_hide_a_teardown_failure() {
        let error = combine_outcome(Ok(7u8), Err(anyhow::anyhow!("seed medium stayed mounted")))
            .expect_err("a VM that could not be stopped is an error");
        assert!(error.to_string().contains("seed medium stayed mounted"));
    }

    #[test]
    fn a_clean_teardown_returns_the_closure_value() {
        assert_eq!(combine_outcome(Ok(7u8), Ok(())).unwrap(), 7);
        assert!(combine_outcome::<u8>(Err(anyhow::anyhow!("boom")), Ok(())).is_err());
    }
}
