use anyhow::Result;
use qlean::{Distro, create_image};
use serial_test::serial;

mod common;
use common::tracing_subscriber_init;

#[tokio::test]
#[serial]
#[ignore]
async fn test_ubuntu_image_creation() -> Result<()> {
    tracing_subscriber_init();

    // Ubuntu uses pre-extracted kernel/initrd - no guestfish needed!
    let image = create_image(Distro::Ubuntu, "ubuntu-noble-cloudimg").await?;

    assert!(image.path().exists(), "qcow2 image must exist");
    assert!(image.kernel().exists(), "kernel must exist");
    assert!(image.initrd().exists(), "initrd must exist");

    println!("✅ Ubuntu image created successfully!");
    println!("   Image:  {}", image.path().display());
    println!("   Kernel: {}", image.kernel().display());
    println!("   Initrd: {}", image.initrd().display());

    Ok(())
}
