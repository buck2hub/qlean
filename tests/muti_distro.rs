use std::str;

use anyhow::Result;
use qlean::{Distro, Image, ImageConfig, MachineConfig, with_machine};
use serial_test::serial;

mod utils;
use utils::tracing_subscriber_init;

#[tokio::test]
#[serial]
async fn test_ubuntu_image() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(ImageConfig::default().with_distro(Distro::Ubuntu)).await?;
    let config = MachineConfig::default();

    with_machine(&image, &config, |vm| {
        Box::pin(async {
            let result = vm.exec(". /etc/os-release && echo $ID").await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "ubuntu");

            Ok(())
        })
    })
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_fedora_image() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(ImageConfig::default().with_distro(Distro::Fedora)).await?;
    let config = MachineConfig::default();

    with_machine(&image, &config, |vm| {
        Box::pin(async {
            let result = vm.exec(". /etc/os-release && echo $ID").await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "fedora");

            Ok(())
        })
    })
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_arch_image() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(ImageConfig::default().with_distro(Distro::Arch)).await?;
    let config = MachineConfig::default();

    with_machine(&image, &config, |vm| {
        Box::pin(async {
            let result = vm.exec(". /etc/os-release && echo $ID").await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "arch");

            Ok(())
        })
    })
    .await?;

    Ok(())
}
