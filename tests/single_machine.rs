use std::path::Path;

use qlean::{Distro, MachineConfig};
use tracing_subscriber::{filter::EnvFilter, fmt::time::LocalTime};

#[tokio::test]
async fn hello() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_timer(LocalTime::rfc_3339())
        .init();

    let image = qlean::create_image(Distro::Debian, "debian-13-generic-amd64").await?;
    let config = MachineConfig::default();

    qlean::with_machine(&image, &config, |vm| {
        Box::pin(async {
            // Here you can interact with the VM
            let result = vm.exec("whoami").await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "root");

            Ok(())
        })
    })
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_file_transfer() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let image = qlean::create_image(Distro::Debian, "debian-13-generic-amd64").await?;
    let config = MachineConfig::default();

    qlean::with_machine(&image, &config, |vm| {
        Box::pin(async {
            // Create test file
            let test_file_content = b"Hello, Qlean!";
            let test_file = tempfile::NamedTempFile::new()?;
            let test_file_name = test_file.path().file_name().unwrap().to_str().unwrap();
            let test_file_recv = tempfile::NamedTempFile::new()?;
            tokio::fs::write(test_file.path(), test_file_content).await?;

            // Test single file upload
            vm.upload(test_file.path(), Path::new("/tmp")).await?;
            let result = vm.exec(format!("cat /tmp/{}", test_file_name)).await?;
            assert!(result.status.success());
            assert_eq!(
                str::from_utf8(&result.stdout)?.trim(),
                str::from_utf8(test_file_content)?.trim()
            );

            // Test single file download
            vm.download(
                Path::new(&format!("/tmp/{}", test_file_name)),
                test_file_recv.path(),
            )
            .await?;
            let downloaded_content = tokio::fs::read(test_file_recv.path()).await?;
            assert_eq!(downloaded_content, test_file_content);

            // Create test directory
            // tempdir()
            // ├─ One
            // │  └─ val.txt (contains "Number 1")
            // ├─ Two.txt (contains "Number 2")
            // └─ Three.txt (contains "Number 3")
            let test_dir = tempfile::tempdir()?;
            let test_dir_name = test_dir.path().file_name().unwrap().to_str().unwrap();
            let dir_one = test_dir.path().join("One");
            tokio::fs::create_dir(&dir_one).await?;
            let val_path = dir_one.join("val.txt");
            tokio::fs::write(&val_path, b"Number 1").await?;
            let file_two = test_dir.path().join("Two.txt");
            let file_three = test_dir.path().join("Three.txt");
            tokio::fs::write(&file_two, b"Number 2").await?;
            tokio::fs::write(&file_three, b"Number 3").await?;
            let test_dir_recv = tempfile::tempdir()?;

            // Test directory upload
            vm.upload(test_dir.path(), Path::new("/tmp")).await?;
            let result = vm
                .exec(format!("cat /tmp/{}/One/val.txt", test_dir_name))
                .await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "Number 1");
            let result = vm
                .exec(format!("cat /tmp/{}/Two.txt", test_dir_name))
                .await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "Number 2");
            let result = vm
                .exec(format!("cat /tmp/{}/Three.txt", test_dir_name))
                .await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "Number 3");

            // Test directory download
            vm.download(
                Path::new(&format!("/tmp/{}", test_dir_name)),
                test_dir_recv.path(),
            )
            .await?;
            let downloaded_path = test_dir_recv.path().join(test_dir_name);
            let downloaded_val =
                tokio::fs::read_to_string(downloaded_path.join("One").join("val.txt")).await?;
            assert_eq!(downloaded_val, "Number 1");
            let downloaded_two = tokio::fs::read_to_string(downloaded_path.join("Two.txt")).await?;
            assert_eq!(downloaded_two, "Number 2");
            let downloaded_three =
                tokio::fs::read_to_string(downloaded_path.join("Three.txt")).await?;
            assert_eq!(downloaded_three, "Number 3");

            Ok(())
        })
    })
    .await?;

    Ok(())
}
