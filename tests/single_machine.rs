use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::Result;
use qlean::{Distro, MachineConfig, create_image, with_machine};

#[path = "support/logging.rs"]
mod logging;
use logging::tracing_subscriber_init;

#[tokio::test]
async fn hello() -> Result<()> {
    tracing_subscriber_init();

    let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
    let config = MachineConfig::default();

    with_machine(&image, &config, |vm| {
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
async fn test_file_transfer() -> Result<()> {
    tracing_subscriber_init();

    let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
    let config = MachineConfig::default();

    with_machine(&image, &config, |vm| {
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

#[tokio::test]
async fn test_file_operation() -> Result<()> {
    tracing_subscriber_init();

    let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
    let config = MachineConfig::default();

    with_machine(&image, &config, |vm| {
        Box::pin(async {
            let base_dir_cmd = vm.exec("mkdir -p /tmp/qlean").await?;
            assert!(base_dir_cmd.status.success());
            let base_dir = PathBuf::from("/tmp/qlean");

            // create_dir & create_dir_all
            let single_dir = base_dir.join("single");
            vm.create_dir(&single_dir).await?;
            let nested_dir = base_dir.join("nested/child");
            vm.create_dir_all(&nested_dir).await?;
            assert!(vm.exists(&single_dir).await?);
            assert!(vm.exists(&nested_dir).await?);
            assert!(!vm.exists(base_dir.join("missing")).await?);

            // write, read, read_to_string, metadata, set_permissions
            let file_path = base_dir.join("hello.txt");
            let file_content = b"Filesystem test";
            vm.write(&file_path, file_content).await?;
            let read_bytes = vm.read(&file_path).await?;
            assert_eq!(read_bytes, file_content);
            let read_string = vm.read_to_string(&file_path).await?;
            assert_eq!(read_string, "Filesystem test");

            let meta = vm.metadata(&file_path).await?;
            assert!(meta.file_type().is_file());
            assert_eq!(meta.len(), file_content.len() as u64);

            vm.set_permissions(&file_path, Permissions::from_mode(0o600))
                .await?;
            let meta = vm.metadata(&file_path).await?;
            assert!(
                meta.permissions
                    .map(|p| p & 0o777 == 0o600)
                    .unwrap_or(false)
            );

            // copy, rename, hard_link
            let copy_path = base_dir.join("copy.txt");
            vm.copy(&file_path, &copy_path).await?;
            assert_eq!(vm.read(&copy_path).await?, file_content);

            let renamed_path = base_dir.join("renamed.txt");
            vm.rename(&copy_path, &renamed_path).await?;
            assert!(vm.exists(&renamed_path).await?);
            assert!(!vm.exists(&copy_path).await?);

            let hard_link_path = base_dir.join("hard.txt");
            vm.hard_link(&file_path, &hard_link_path).await?;
            assert_eq!(vm.read(&hard_link_path).await?, file_content);

            // read_link
            let symlink_path = base_dir.join("symlink.txt");
            let symlink_cmd = format!("ln -s {} {}", file_path.display(), symlink_path.display());
            let symlink_res = vm.exec(&symlink_cmd).await?;
            assert!(symlink_res.status.success());
            let target = vm.read_link(&symlink_path).await?;
            assert_eq!(target, file_path);

            // read_dir
            let mut entries = vm.read_dir(&base_dir).await?;
            let mut names = Vec::new();
            while let Some(entry) = entries.next() {
                names.push(entry.file_name());
            }
            assert!(names.contains(&"hello.txt".to_string()));
            assert!(names.contains(&"renamed.txt".to_string()));
            assert!(names.contains(&"hard.txt".to_string()));
            assert!(names.contains(&"symlink.txt".to_string()));
            assert!(names.contains(&"single".to_string()));

            // remove_file & remove_dir_all
            vm.remove_file(&renamed_path).await?;
            vm.remove_file(&hard_link_path).await?;
            vm.remove_file(&symlink_path).await?;
            vm.remove_file(&file_path).await?;
            vm.remove_dir_all(&nested_dir).await?;
            vm.remove_dir_all(&base_dir.join("nested")).await?;
            vm.remove_dir_all(&single_dir).await?;
            vm.remove_dir_all(&base_dir).await?;
            assert!(!vm.exists(&base_dir).await?);

            Ok(())
        })
    })
    .await?;

    Ok(())
}
