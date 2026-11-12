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

use anyhow::{Context, Result, bail};
use qlean::{GuestOs, Image, ImageConfig, Machine, MachineConfig, MachinePool};
use serial_test::serial;

mod utils;
use utils::tracing_subscriber_init;

/// Command lines of the live host processes whose argv contains `needle`.
///
/// The Windows smoke tests are the only evidence this project will ever have for a guest it
/// cannot inspect, so "the TPM state was reused" and "no `swtpm` was left behind" have to be
/// observable facts, not comments. Both are visible without the guest: the `swtpm` and QEMU
/// command lines carry the per-VM paths. `/proc` is the cheapest way to read them and this test
/// only ever runs on Linux KVM hosts.
fn host_processes_matching(needle: &str) -> Vec<(u32, String)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let argv: Vec<String> = raw
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        let line = argv.join(" ");
        if line.contains(needle) {
            found.push((pid, line));
        }
    }
    found.sort_by_key(|(pid, _)| *pid);
    found
}

/// Processes that `after` has and `before` does not, by pid.
fn newly_started(before: &[(u32, String)], after: &[(u32, String)]) -> Vec<(u32, String)> {
    after
        .iter()
        .filter(|(pid, _)| !before.iter().any(|(seen, _)| seen == pid))
        .cloned()
        .collect()
}

/// The `file=` of the QEMU argument that attaches the per-VM OVMF vars pflash unit.
fn pflash_vars_file(arguments: &str) -> Option<String> {
    arguments.split(' ').find_map(|argument| {
        if !argument.starts_with("if=pflash") || !argument.contains("unit=1") {
            return None;
        }
        argument
            .split(',')
            .find_map(|part| part.strip_prefix("file=").map(str::to_owned))
    })
}

/// The `file=` of the QEMU argument that boots the guest disk overlay.
///
/// The overlay is `if=virtio` with a writeback cache while the seed medium is an IDE CD-ROM,
/// so "the drive the guest boots from" is distinguishable from "the medium it deploys from".
fn overlay_disk_file(arguments: &str) -> Option<String> {
    arguments.split(' ').find_map(|argument| {
        if !argument.contains("cache=writeback") {
            return None;
        }
        argument
            .split(',')
            .find_map(|part| part.strip_prefix("file=").map(str::to_owned))
    })
}

/// The `file=` of the QEMU argument that attaches the seed medium as a CD-ROM.
fn seed_iso_file(arguments: &str) -> Option<String> {
    arguments.split(' ').find_map(|argument| {
        if !argument.contains("media=cdrom") {
            return None;
        }
        argument
            .split(',')
            .find_map(|part| part.strip_prefix("file=").map(str::to_owned))
    })
}

/// Whether the guest is attached to any CD-ROM at all.
fn has_cdrom(arguments: &str) -> bool {
    arguments
        .split(' ')
        .any(|part| part.contains("media=cdrom"))
}

/// The `dir=` of the `swtpm --tpmstate` argument.
fn tpm_state_dir(arguments: &str) -> Option<String> {
    let mut parts = arguments.split(' ');
    while let Some(part) = parts.next() {
        if part == "--tpmstate"
            && let Some(value) = parts.next()
        {
            return value.strip_prefix("dir=").map(str::to_owned);
        }
    }
    None
}

/// The host-process helpers are the eyes of the firmware lifecycle test.
///
/// They run on every CI host (no Windows image needed) because a helper that silently returns
/// `None` would turn "the restart reused the same vars" into a panic on the one host that has a
/// licensed image, after a 15 minute boot. Parsing is checked here against the exact argument
/// shapes `src/qemu.rs` and `src/firmware.rs` produce.
#[test]
fn the_host_process_helpers_parse_the_paths_the_launch_builds() {
    let arguments = "qemu-system-x86_64 -drive if=pflash,format=raw,readonly=on,unit=0,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd                      -drive if=pflash,format=raw,unit=1,file=/run/qlean/VM-1/ovmf_vars.fd";
    assert_eq!(
        pflash_vars_file(arguments).as_deref(),
        Some("/run/qlean/VM-1/ovmf_vars.fd"),
        "the per-VM vars are the pflash unit=1, not the read-only code image"
    );

    let swtpm = "swtpm socket --tpm2 --tpmstate dir=/run/qlean/VM-1/tpm                  --ctrl type=unixio,path=/run/qlean/VM-1/swtpm.sock,mode=0600";
    assert_eq!(tpm_state_dir(swtpm).as_deref(), Some("/run/qlean/VM-1/tpm"));

    // The shapes below are the ones `qemu.rs` builds: `seed_drive_option` and
    // `disk_drive_option`. A fixture that drifts from them tests the fixture.
    let seeded = "qemu-system-x86_64 -drive file=/run/qlean/VM-1/seed.iso,if=ide,media=cdrom,readonly=on \
                   -drive file=/run/qlean/VM-1/overlay.img,if=virtio,cache=writeback";
    assert_eq!(
        seed_iso_file(seeded).as_deref(),
        Some("/run/qlean/VM-1/seed.iso"),
        "the deployment medium is the CD-ROM, not the disk overlay"
    );
    assert!(has_cdrom(seeded));
    let after_deployment =
        "qemu-system-x86_64 -drive file=/run/qlean/VM-1/overlay.img,if=virtio,cache=writeback";
    assert_eq!(seed_iso_file(after_deployment), None);
    assert!(
        !has_cdrom(after_deployment),
        "a boot without the seed medium must not attach any CD-ROM"
    );
    assert_eq!(
        overlay_disk_file(seeded).as_deref(),
        Some("/run/qlean/VM-1/overlay.img"),
        "the guest boots from the overlay, not from the deployment medium"
    );
    assert_eq!(
        tpm_state_dir("swtpm socket --tpm2 --ctrl type=unixio"),
        None
    );

    let before = vec![(10, "a".to_string())];
    let after = vec![(10, "a".to_string()), (11, "b".to_string())];
    assert_eq!(newly_started(&before, &after), vec![(11, "b".to_string())]);

    // A needle that no process can carry must find nothing: the scan reads argv, not the name of
    // any particular binary.
    assert!(
        host_processes_matching("qlean-this-needle-cannot-exist-4f2a").is_empty(),
        "the /proc scan matched a process for an impossible needle"
    );
}

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
    // Being a file is not being a qcow2. A Linux disk or a stray text file would boot far
    // enough to burn the whole deployment budget and then fail with "the guest address was
    // never obtained", which points nowhere near the wrong variable.
    let magic = {
        use std::io::Read;
        let mut magic = [0u8; 4];
        std::fs::File::open(&path)
            .and_then(|mut file| file.read_exact(&mut magic))
            .with_context(|| format!("QLEAN_WINDOWS_IMAGE={path} could not be read"))?;
        magic
    };
    if magic != [0x51, 0x46, 0x49, 0xfb] {
        bail!(
            "QLEAN_WINDOWS_IMAGE={path} is not a qcow2 image: it starts with {magic:02x?}, but qcow2 \
             starts with [51, 46, 49, fb]. Point the variable at the licensed Windows qcow2 (DEP-01)"
        );
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

    // First boot lays down per-VM OVMF vars and TPM state. `is_running` only speaks for QEMU,
    // so the firmware and the TPM are checked on the host: their processes and the per-VM paths
    // on their command lines are the only observation a Windows guest allows.
    let swtpm_before = host_processes_matching("swtpm socket");
    let qemu_before = host_processes_matching("qemu-system");
    vm.init().await?;
    assert!(vm.is_running().await?);

    let swtpm_now = newly_started(&swtpm_before, &host_processes_matching("swtpm socket"));
    assert_eq!(
        swtpm_now.len(),
        1,
        "the first boot must start exactly one swtpm: {swtpm_now:#?}"
    );
    let (vars, overlay) = {
        let qemu = newly_started(&qemu_before, &host_processes_matching("qemu-system"));
        assert_eq!(
            qemu.len(),
            1,
            "the first boot must start one QEMU: {qemu:#?}"
        );
        let (_, arguments) = &qemu[0];
        let vars = pflash_vars_file(arguments)
            .unwrap_or_else(|| panic!("QEMU has no per-VM vars pflash: {arguments}"));
        assert!(
            std::path::Path::new(&vars).is_file(),
            "OVMF vars {vars} must exist on the host after the first boot"
        );
        let overlay = overlay_disk_file(arguments)
            .unwrap_or_else(|| panic!("QEMU has no guest disk overlay: {arguments}"));
        (vars, overlay)
    };
    let tpm_dir = tpm_state_dir(&swtpm_now[0].1)
        .unwrap_or_else(|| panic!("swtpm has no --tpmstate dir: {}", swtpm_now[0].1));
    assert!(
        std::path::Path::new(&tpm_dir).is_dir(),
        "TPM state {tpm_dir} must be a directory during the first boot"
    );

    // QMP/ACPI shutdown must stop the guest and the swtpm process.
    vm.shutdown().await?;
    assert!(!vm.is_running().await?);
    let leaked = host_processes_matching(&tpm_dir);
    assert!(
        leaked.is_empty(),
        "shutdown left a process holding TPM state {tpm_dir}: {leaked:#?}"
    );

    // Restart reuses the same overlay, OVMF vars and TPM state: same files (all three are read
    // back off the restarted QEMU and swtpm command lines), and a TPM state that was written
    // during the first boot instead of a fresh one.
    assert!(
        std::fs::read_dir(&tpm_dir)
            .map(|entries| entries
                .flatten()
                .any(|entry| entry.metadata().map(|meta| meta.len() > 0).unwrap_or(false)))
            .unwrap_or(false),
        "the TPM state directory {tpm_dir} is empty: nothing was persisted to reuse"
    );
    vm.spawn().await?;
    assert!(vm.is_running().await?);
    let vars_again = {
        let qemu = newly_started(&qemu_before, &host_processes_matching("qemu-system"));
        assert_eq!(qemu.len(), 1, "the restart must start one QEMU: {qemu:#?}");
        let (_, arguments) = &qemu[0];
        pflash_vars_file(arguments)
            .unwrap_or_else(|| panic!("QEMU has no per-VM vars pflash: {arguments}"))
    };
    assert_eq!(
        vars_again, vars,
        "the restart booted with different OVMF vars, so the first boot's NVRAM was dropped"
    );
    {
        let qemu = newly_started(&qemu_before, &host_processes_matching("qemu-system"));
        let (_, arguments) = &qemu[0];
        let overlay_again = overlay_disk_file(arguments)
            .unwrap_or_else(|| panic!("the restarted QEMU has no guest disk: {arguments}"));
        assert_eq!(
            overlay_again, overlay,
            "the restart booted a different disk, so the deployed installation was left behind"
        );
        assert!(
            std::path::Path::new(&overlay_again).is_file(),
            "the overlay {overlay_again} is gone after the restart"
        );
    }
    let tpm_dir_again =
        tpm_state_dir(&newly_started(&swtpm_before, &host_processes_matching("swtpm socket"))[0].1)
            .expect("the restarted swtpm has no --tpmstate dir");
    assert_eq!(
        tpm_dir_again, tpm_dir,
        "the restart used a different TPM state directory, so the vTPM started over"
    );
    vm.shutdown().await?;
    assert!(!vm.is_running().await?);
    let leaked = host_processes_matching(&tpm_dir);
    assert!(
        leaked.is_empty(),
        "the second shutdown left a process holding TPM state {tpm_dir}: {leaked:#?}"
    );

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

    let qemu_before = host_processes_matching("qemu-system");
    vm.init().await?;
    // The seed medium is what makes a first boot a deployment, and it must be gone once the
    // marker appeared: a deployed guest that keeps a readable seed ISO is a contract leak.
    let seed = {
        let qemu = newly_started(&qemu_before, &host_processes_matching("qemu-system"));
        assert_eq!(
            qemu.len(),
            1,
            "the first boot must start one QEMU: {qemu:#?}"
        );
        let (_, arguments) = &qemu[0];
        seed_iso_file(arguments)
            .unwrap_or_else(|| panic!("the first boot has no seed CD-ROM: {arguments}"))
    };
    assert!(
        !std::path::Path::new(&seed).exists(),
        "the seed medium {seed} is still on the host after the deployment marker appeared"
    );
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
    {
        let qemu = newly_started(&qemu_before, &host_processes_matching("qemu-system"));
        assert_eq!(qemu.len(), 1, "the restart must start one QEMU: {qemu:#?}");
        let (_, arguments) = &qemu[0];
        assert!(
            !has_cdrom(arguments),
            "the restarted guest still has a CD-ROM attached: {arguments}"
        );
    }
    let out = vm.exec("cmd /c echo spawned").await?;
    assert!(String::from_utf8_lossy(&out.stdout).contains("spawned"));
    // The pinned key survives the reboot because it is the key installed in the image.
    assert_eq!(vm.ssh_host_key().unwrap(), pinned);

    // The one-shot deployment really consumed its seed: a second `init` is refused
    // instead of booting a guest whose installed host key would no longer match.
    let err = vm
        .init()
        .await
        .expect_err("a deployed Windows guest must not be initialized again");
    assert!(err.to_string().contains("already completed"), "{err}");

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

/// `get_ip` for Windows guests: the first query resolves this VM's lease, the next call is
/// served from the cache, and after a restart - with another pool member's lease in the same
/// table - the fresh query still answers with this VM's own address.
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

    // A restart drops the cached address, so the next call has to query the guest again. The
    // table now holds another VM's lease as well, which is what makes this a test of the MAC
    // filter rather than of the cache: losing it would surface as `other_ip` here.
    vm.shutdown().await?;
    vm.spawn().await?;
    assert_eq!(
        vm.get_ip().await?,
        ip,
        "the fresh query after a restart lost this VM's own lease"
    );

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

    // Every POSIX-only operation must fail loudly on Windows, so one hardware run
    // proves all three entry points rather than only the symbolic-link reader.
    let err = vm
        .read_link(&remote_file)
        .await
        .expect_err("read_link must be rejected")
        .to_string();
    assert!(err.contains("read_link"), "{err}");

    let err = vm
        .hard_link(&remote_file, root.join("hard link.txt"))
        .await
        .expect_err("hard_link must be rejected")
        .to_string();
    assert!(err.contains("hard_link"), "{err}");

    let perms = std::fs::metadata(&host_file)?.permissions();
    let err = vm
        .set_permissions(&remote_file, perms)
        .await
        .expect_err("set_permissions must be rejected")
        .to_string();
    assert!(err.contains("set_permissions"), "{err}");

    vm.remove_dir_all(root).await?;
    vm.shutdown().await?;
    Ok(())
}
