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
use qlean::{GuestOs, Image, ImageConfig, Machine, MachineConfig, MachinePool};
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

/// Transport: address discovery, pinned host key, reconnect after shutdown, and
/// the explicit unsupported answer for interactive PTYs.
#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01) and a Windows KVM host (DEP-02)"]
#[serial]
async fn windows_transport() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    let mut vm = Machine::new(&image, &MachineConfig::default()).await?;
    let pinned = vm
        .ssh_host_key()
        .ok_or_else(|| anyhow::anyhow!("Windows guests must expose a per-VM SSH host key"))?
        .to_string();

    vm.init().await?;
    // The leased address is discovered from libvirt, never read inside the guest.
    let ip = vm.get_ip().await?;
    assert!(
        ip.parse::<std::net::IpAddr>().is_ok(),
        "unexpected ip: {ip}"
    );
    assert_eq!(vm.ssh_host_key().unwrap(), pinned);

    // Interactive PTYs are not supported for Windows guests and must fail without
    // spawning a vsock connection.
    let err = vm.open_interactive_shell(80, 24).await.err();
    let message = err.map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains("not supported"), "{message}");

    vm.shutdown().await?;
    assert!(!vm.is_running().await?);

    // `spawn` reconnects without re-attaching the seed medium.
    vm.spawn().await?;
    let out = vm.exec("cmd /c echo spawned").await?;
    assert!(String::from_utf8_lossy(&out.stdout).contains("spawned"));
    vm.shutdown().await?;

    Ok(())
}

/// Two Windows VMs in one pool must not share addresses, host keys or sessions.
#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01) and a Windows KVM host (DEP-02)"]
#[serial]
async fn windows_pool() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    let mut pool = MachinePool::new();
    pool.add("win-a", &image, &MachineConfig::default()).await?;
    pool.add("win-b", &image, &MachineConfig::default()).await?;
    pool.init_all().await?;

    let mut addresses = Vec::new();
    let mut host_keys = Vec::new();
    for name in ["win-a", "win-b"] {
        let mut machine = pool
            .get(name)
            .await
            .ok_or_else(|| anyhow::anyhow!("machine {name} missing from the pool"))?;
        addresses.push(machine.get_ip().await?);
        host_keys.push(
            machine
                .ssh_host_key()
                .ok_or_else(|| anyhow::anyhow!("{name} is missing its per-VM host key"))?
                .to_string(),
        );
        let out = machine.exec("cmd /c hostname").await?;
        assert!(out.status.success(), "{name} is not reachable");
    }

    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 2, "pool machines share an address");
    host_keys.sort();
    host_keys.dedup();
    assert_eq!(host_keys.len(), 2, "pool machines share a host key");

    pool.shutdown_all().await?;
    Ok(())
}

/// PowerShell `exec` semantics: verbatim command strings, separated streams and the
/// exit-code contract from ADR-WIN-05.
#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01) and a Windows KVM host (DEP-02)"]
#[serial]
async fn windows_exec() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    let mut vm = Machine::new(&image, &MachineConfig::default()).await?;
    vm.init().await?;

    // An empty command has no defined result and must be refused before hitting SSH.
    let err = vm.exec("   ").await.expect_err("empty command must fail");
    assert!(err.to_string().contains("non-empty"), "{err}");

    // `whoami` succeeds and reports the documented deployment account.
    let whoami = vm.exec("whoami").await?;
    assert!(whoami.status.success());
    assert_eq!(whoami.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&whoami.stdout)
            .to_ascii_lowercase()
            .contains("qlean"),
        "unexpected whoami output"
    );

    // Quotes and spaces reach PowerShell verbatim instead of being re-split by a host
    // shell or escaped as a POSIX argument.
    let quoted = vm.exec("Write-Output 'a b  c'").await?;
    assert_eq!(
        String::from_utf8_lossy(&quoted.stdout).trim(),
        "a b  c",
        "quoting/whitespace was reinterpreted"
    );

    // A non-zero exit code is a failure and is retrievable unchanged.
    let failing = vm.exec("cmd /c exit 3").await?;
    assert!(!failing.status.success());
    assert_eq!(failing.status.code(), Some(3));

    // stderr stays on its own stream while stdout is unaffected.
    let streams = vm
        .exec("Write-Output out; [Console]::Error.WriteLine('err')")
        .await?;
    assert!(String::from_utf8_lossy(&streams.stdout).contains("out"));
    assert!(String::from_utf8_lossy(&streams.stderr).contains("err"));
    assert!(!String::from_utf8_lossy(&streams.stdout).contains("err"));

    // Exit codes above 255 cannot be represented and must not be truncated.
    let large = vm.exec("cmd /c exit 300").await;
    let err = large.expect_err("exit code 300 must be rejected");
    assert!(err.to_string().contains("300"), "{err}");

    vm.shutdown().await?;
    Ok(())
}

/// `get_ip` for Windows guests: the transport's address is cached, and a fresh query must
/// match this VM's own MAC rather than another pool member's lease.
#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01) and a Windows KVM host (DEP-02)"]
#[serial]
async fn windows_get_ip() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    let mut vm = Machine::new(&image, &MachineConfig::default()).await?;
    vm.init().await?;

    let ip = vm.get_ip().await?;
    assert!(
        ip.parse::<std::net::IpAddr>().is_ok(),
        "unexpected ip: {ip}"
    );
    // A second call is served from the cache and must report the same address.
    assert_eq!(vm.get_ip().await?, ip);

    // Two machines on the same network keep distinct addresses.
    let mut other = Machine::new(&image, &MachineConfig::default()).await?;
    other.init().await?;
    let other_ip = other.get_ip().await?;
    assert_ne!(ip, other_ip, "pool members share an address");

    vm.shutdown().await?;
    other.shutdown().await?;
    Ok(())
}

/// Windows file semantics: upload/download round-trip (files and directories), recursive
/// delete, rename and copy, plus the explicit rejections for POSIX-only operations.
#[tokio::test]
#[ignore = "needs a licensed Windows image (DEP-01) and a Windows KVM host (DEP-02)"]
#[serial]
async fn windows_files() -> Result<()> {
    tracing_subscriber_init();

    let image = Image::new(windows_image_config()?).await?;
    let mut vm = Machine::new(&image, &MachineConfig::default()).await?;
    vm.init().await?;

    let root = std::path::Path::new(r"C:\qlean-fs-test");
    let nested = root.join("nested dir");
    let unicode = nested.join("döner 报告.txt");
    let contents = b"qlean windows file round-trip\n";

    // Directories, spaces and non-ASCII names.
    vm.create_dir_all(&nested).await?;
    assert!(vm.exists(&nested).await?);
    vm.write(&unicode, contents).await?;
    assert_eq!(vm.read(&unicode).await?, contents);
    assert_eq!(
        vm.read_to_string(&unicode).await?,
        std::str::from_utf8(contents)?
    );

    // Copy must not depend on POSIX `cp`.
    let copied = nested.join("copied.txt");
    vm.copy(&unicode, &copied).await?;
    assert_eq!(vm.read(&copied).await?, contents);

    // Rename and recursive delete.
    let renamed = nested.join("renamed.txt");
    vm.rename(&copied, &renamed).await?;
    assert!(!vm.exists(&copied).await?);
    assert!(vm.exists(&renamed).await?);
    vm.remove_dir_all(root).await?;
    assert!(!vm.exists(root).await?);

    // File and directory upload/download round-trip from the host.
    let host = tempfile::tempdir()?;
    let host_file = host.path().join("upload me.txt");
    std::fs::write(&host_file, contents)?;
    let tree = host.path().join("tree");
    std::fs::create_dir_all(tree.join("sub dir"))?;
    std::fs::write(tree.join("sub dir").join("a.txt"), contents)?;

    let remote_file = root.join("upload me.txt");
    vm.upload(&host_file, &remote_file).await?;
    assert_eq!(vm.read(&remote_file).await?, contents);

    let remote_tree = root.join("tree");
    vm.upload(&tree, root).await?;
    assert!(
        vm.exists(&remote_tree.join("sub dir").join("a.txt"))
            .await?
    );

    let download_dir = host.path().join("downloaded");
    std::fs::create_dir_all(&download_dir)?;
    vm.download(&remote_tree, &download_dir).await?;
    let downloaded = download_dir.join("tree").join("sub dir").join("a.txt");
    assert!(downloaded.is_file());
    assert_eq!(std::fs::read(&downloaded)?, contents);

    // POSIX-only operations must fail loudly on Windows.
    let err = vm
        .read_link(&remote_file)
        .await
        .expect_err("read_link must be rejected")
        .to_string();
    assert!(err.contains("read_link"), "{err}");

    vm.remove_dir_all(root).await?;
    vm.shutdown().await?;
    Ok(())
}
