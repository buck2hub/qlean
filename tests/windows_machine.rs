//! Windows guest integration tests.
//!
//! These tests need a licensed Windows qcow2 (`DEP-01`) and a Linux KVM host with
//! OVMF, `swtpm` and libvirt (`DEP-02`). They are `#[ignore]`d so that the CI gate
//! (`cargo test --no-run`) only has to compile them.
//!
//! Run them on a prepared host with:
//!
//! ```text
//! QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 \
//! QLEAN_WINDOWS_DIGEST=sha256:<hex> \
//!   cargo test --test windows_machine -- --ignored --test-threads=1
//! ```
//!
//! Without both environment variables every test returns an explanatory error
//! instead of silently skipping.

use anyhow::{Result, bail};
use qlean::{GuestOs, Image, ImageConfig, Machine, MachineConfig};
use serial_test::serial;

mod utils;
use utils::tracing_subscriber_init;

/// Build a Windows `ImageConfig` from the test environment.
fn windows_image_config() -> Result<ImageConfig> {
    let path = std::env::var("QLEAN_WINDOWS_IMAGE").map_err(|_| {
        anyhow::anyhow!(
            "QLEAN_WINDOWS_IMAGE must point at a licensed Windows qcow2 (DEP-01) to run this test"
        )
    })?;
    let digest = std::env::var("QLEAN_WINDOWS_DIGEST").map_err(|_| {
        anyhow::anyhow!(
            "QLEAN_WINDOWS_DIGEST must be the sha256:<hex> of QLEAN_WINDOWS_IMAGE (DEP-01)"
        )
    })?;
    if !std::path::Path::new(&path).is_file() {
        bail!("QLEAN_WINDOWS_IMAGE={path} is not a readable qcow2 file");
    }
    Ok(ImageConfig::default()
        .with_guest_os(GuestOs::Windows)
        .with_source(path)
        .with_digest(digest))
}

#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01) and a Windows KVM host (DEP-02)"]
#[serial]
async fn windows_firmware_lifecycle() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    assert_eq!(image.guest_os(), GuestOs::Windows);

    let config = MachineConfig::default();
    let mut vm = Machine::new(&image, &config).await?;
    assert_eq!(vm.guest_os(), GuestOs::Windows);

    // First boot lays down per-VM OVMF vars and TPM state.
    vm.init().await?;
    assert!(vm.is_running().await?);

    // QMP/ACPI shutdown must stop the guest and the swtpm process.
    vm.shutdown().await?;
    assert!(!vm.is_running().await?);

    // Restart reuses the same overlay, OVMF vars and TPM state.
    vm.spawn().await?;
    assert!(vm.is_running().await?);
    vm.shutdown().await?;

    Ok(())
}

/// First boot must deploy the seed medium and leave a usable SSH identity.
///
/// Needs the TCP transport from `TRN-01` to reach the guest, so it stays `#[ignore]`d
/// together with the other Windows tests.
#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01), a Windows KVM host (DEP-02) and the TCP transport (TRN-01)"]
#[serial]
async fn windows_first_boot() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    let mut vm = Machine::new(&image, &MachineConfig::default()).await?;

    // The per-VM host key exists before boot and is exposed for pinning.
    let host_key = vm
        .ssh_host_key()
        .ok_or_else(|| anyhow::anyhow!("Windows guests must expose a per-VM SSH host key"))?;
    assert!(host_key.starts_with("ssh-ed25519 "), "{host_key}");

    vm.init().await?;
    let deployed = vm
        .exec(r"cmd /c if exist C:\ProgramData\qlean\deployed echo deployed")
        .await?;
    assert!(
        String::from_utf8_lossy(&deployed.stdout).contains("deployed"),
        "first-boot deployment marker missing: {deployed:?}"
    );

    // The guest path contract must have installed the key for the qlean account.
    let keys = vm
        .exec("cmd /c type C:\\ProgramData\\ssh\\administrators_authorized_keys")
        .await?;
    assert!(String::from_utf8_lossy(&keys.stdout).contains("ssh-ed25519"));

    vm.shutdown().await?;
    Ok(())
}
