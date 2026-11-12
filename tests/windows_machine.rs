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
