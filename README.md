# Qlean

**Qlean** is a system-level isolation testing library built on QEMU/KVM. It spins up lightweight VMs in your Rust tests so privileged or risky operations stay off the host.

## Overview

Qlean targets two common needs in system-level testing:

**1. Complete Resource Isolation**

Some tests need root privileges or direct access to kernel interfaces. Running them on the host can leave the machine in a bad state when a test fails. Qlean runs each test in its own VM so failures stay contained and the host stays stable.

**2. Convenient Distributed Testing**

For distributed or multi-node scenarios, Qlean lets you create and coordinate several VMs from test code—no separate cluster setup or orchestration layer required.

## Key Features

- 🔒 **Complete Isolation**: Based on QEMU/KVM, providing full virtual machine isolation
- 🔄 **Distributed Testing**: Easily create and manage multiple virtual machines
- 🛡️ **RAII-style Interface**: Automatic resource management ensures VMs are properly cleaned up
- 📦 **Out-of-the-Box**: Automated image downloading with verification, no manual configuration needed
- 🐧 **Linux Native**: Native support for Linux hosts with multiple guest distributions and architectures

## Usage

### Host Setup

#### Install CLI tools

Install and configure QEMU, libvirt, and xorriso on your Linux host before using Qlean. On Debian or Ubuntu, see [the setup guide](https://buck2hub.com/docs/qlean/setup) for step-by-step instructions.

#### Configure qemu-bridge-helper

Qlean uses `qemu-bridge-helper` to manage networking for multiple virtual machines, so it requires proper configuration.

Grant `CAP_NET_ADMIN` to the default network helper:

```bash
sudo chmod u-s /usr/lib/qemu/qemu-bridge-helper
sudo setcap cap_net_admin+ep /usr/lib/qemu/qemu-bridge-helper
```

`qemu-bridge-helper` denies all bridges by default, so you must allow the `qlbr0` bridge that Qlean creates:

```bash
sudo mkdir -p /etc/qemu
sudo sh -c 'echo "allow qlbr0" > /etc/qemu/bridge.conf'
sudo chmod 644 /etc/qemu/bridge.conf
```

#### Windows guest prerequisites

Windows guests are KVM-only. On a host that will run `GuestOs::Windows`, additionally install:

| Requirement | Purpose | Check |
|---|---|---|
| KVM (`/dev/kvm`) | Windows guests never fall back to TCG | `test -w /dev/kvm` |
| OVMF UEFI firmware | Windows boots only on UEFI | `ls /usr/share/edk2/x64/OVMF_CODE.4m.fd` (Arch), `ls /usr/share/OVMF/OVMF_CODE_4M.fd` (Debian/Ubuntu) |
| `swtpm` | Per-VM TPM 2.0 device | `command -v swtpm` |

```bash
# Arch
sudo pacman -S qemu-full libvirt edk2-ovmf swtpm xorriso
# Debian / Ubuntu
sudo apt install qemu-system-x86 ovmf swtpm xorriso
```

Qlean locates OVMF by probing the known Arch/Debian/Fedora/Bazzite layouts. Point it at a
specific pair with `QLEAN_OVMF_CODE` and `QLEAN_OVMF_VARS` (both must be set), and override
the TPM binary with `QLEAN_SWTPM`. Secure Boot is used only when the resolved code image is
an OVMF `secboot` build; otherwise the firmware is reported as Secure Boot disabled — Qlean
never silently swaps in a different firmware. For a `secboot` code image Qlean prefers the
Microsoft-enrolled vars template (`OVMF_VARS_4M.ms.fd`, `OVMF_VARS.4m.ms.fd`,
`OVMF_VARS.secboot.fd`) and only falls back to the plain template, which boots in Secure
Boot *setup mode* and is rejected by Windows 11 — pair both variables explicitly if your
distribution names them differently.

| Guest | Minimum (Qlean defaults) | Recommended |
|---|---|---|
| Windows 10 | `core: 2`, `mem: 4096` MB | `core: 4`, `mem: 8192` MB |
| Windows 11 | `core: 2`, `mem: 4096` MB, TPM 2.0 | `core: 4`, `mem: 8192` MB |

The defaults (`core: 2`, `mem: 4096`) match the Windows 10/11 minimums. Leave `disk`
unset so the qcow2 overlay grows on demand, or set it to at least `64` GB to match the
Windows 11 install requirement.

#### Windows image contract

Qlean does not regenerate or specialize an installed Windows image. A Windows image must
already be generalized and ship a first-boot task that consumes Qlean's seed medium:

1. Build the image with the virtio drivers for the devices Qlean attaches
   (`viostor`/`vioscsi` for the disk, `NetKVM` for the network, `vioserial` if you also
   use it), enable the OpenSSH Server optional feature, and pre-generalize it
   (`sysprep /generalize /oobe /shutdown`).
2. Create a local account named `qlean` (a member of `Administrators` is supported). Give
   it no static password for Qlean's own use: Qlean never sets or carries a password, and
   password authentication must stay disabled.
3. Ship a scheduled task that runs on first boot, finds the seed medium by its volume
   label `QLEANSEED`, and then:
   - installs `qlean/authorized_keys` as
     `C:\ProgramData\ssh\administrators_authorized_keys` (administrator accounts) or
     `%USERPROFILE%\.ssh\authorized_keys`, with an ACL that only grants
     `Administrators`, `SYSTEM` and the service account owning the file;
   - installs `qlean/ssh_host_ed25519_key` as `C:\ProgramData\ssh\ssh_host_ed25519_key`
     with the same owner-only ACL, so the host key Qlean pins really is the per-VM key;
   - writes an `sshd_config` with `PubkeyAuthentication yes`, `PasswordAuthentication no`
     and a `sftp` subsystem, sets the OpenSSH default shell to PowerShell
     (`HKLM:\SOFTWARE\OpenSSH` -> `DefaultShell` =
     `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, which Qlean's
     `exec` semantics assume), then restarts `sshd`;
   - writes `C:\ProgramData\qlean\deployed` once all of the above succeeded.
4. Leave the image shut down and unconfigured; Qlean creates a per-VM overlay, a per-VM
   `ovmf_vars.fd`, a per-VM TPM 2.0 state and a per-VM seed medium on every `init`.

The seed medium is appended only on the first boot and is deleted as soon as the guest
reports `C:\ProgramData\qlean\deployed`. It contains the client's *public* key, the
per-VM host *private* key and `qlean/deploy.json`; the client private key stays in the
host secrets directory. The deployment budget is 900s by default (independent of the
Linux SSH connect timeout of 180s/300s) and can be tuned with `MachineConfig::ssh_timeout`.
It bounds both halves of the first boot: waiting for `sshd` to answer and waiting for the
deploy marker, since a guest that is still deploying does not accept connections yet.
Later boots use the plain connect budget again. On timeout Qlean keeps the seed medium and
returns an error naming the expected marker file and this section; the failed VM is torn
down (session closed, QEMU terminated, `swtpm` stopped) so no half-deployed guest survives.
A Windows machine can be initialized only once — after its deployment use `spawn`.

#### Windows transport and security

Windows guests have no vsock, so Qlean reaches them over the libvirt NAT network:

- **Address discovery runs on the host, before SSH.** Qlean polls
  `virsh net-dhcp-leases qlean` for the MAC address it assigned to that VM and caches the
  result on the machine, so `Machine::get_ip` never runs a command inside a Windows guest.
  Discovery and the connection attempt share one bounded budget
  (`MachineConfig::ssh_timeout`); running out of it returns an error listing the leases
  that were actually seen.
- **Host keys are pinned instead of trusted on first use.** Qlean compares the key
  presented by the guest's `sshd` with the per-VM key it generated during deployment. A
  different key, or a certificate where a plain key is pinned, aborts the connection.
  Linux guests keep their historical trust-on-first-use behavior because their vsock
  endpoint is host-local and cannot be redirected to another machine.
- **vsock is a Linux-only requirement.** `with_machine` checks `/dev/vhost-vsock` only
  for `GuestOs::Linux`, and `with_pool` does not require it at all, so a host without
  vhost-vsock can still run Windows guests.
- **Pool isolation.** Each VM gets its own MAC address, DHCP lease, seed medium and host
  key, so pool members never share an address or a pinned key.
- **`get_ip` returns the address Qlean actually used.** For Windows guests
  `Machine::get_ip` returns the address discovered for the transport (cached after the
  first connection). A re-query runs PowerShell inside the guest and keeps only the
  address whose MAC matches the VM's own MAC, so it can never return another VM's lease;
  a missing or ambiguous answer is an error instead of a guess. Linux guests keep the
  existing in-guest query.
- **Interactive PTY shells are not supported for Windows guests.**
  `Machine::open_interactive_shell` returns an actionable error instead of opening a
  half-configured session; use `exec` for commands and SFTP for file transfer.

#### Windows command execution

`Machine::exec` sends the command string to the guest's shell **verbatim**: no argument
escaping, no re-quoting and no POSIX translation is applied on any guest OS. Windows
guests run it in PowerShell (see the image contract above), so write PowerShell syntax:

```rust
let out = machine.exec(r#"Write-Output "hello from $env:COMPUTERNAME""#).await?;
assert!(out.status.success());
```

The reported status follows `std::process::ExitStatus` semantics on every guest OS,
which is what makes Windows results meaningful:

- `status.success()` is true only for exit code `0`.
- `status.code()` returns `0..=255` unchanged.
- Exit codes outside `0..=255` (for example a Windows failure such as `0xC0000005`) are
  reported as an error instead of being truncated into a smaller, misleading code.
- stdout and stderr are kept in separate buffers as raw bytes.
- An empty or whitespace-only command is rejected with an error before any SSH request is
  sent.

#### Windows file operations

Every remote path is converted to a guest path before it reaches SFTP
(`GuestPath`), so a Windows drive path is never reinterpreted with host `Path`
semantics. Both `/` and `\` are accepted on input, and paths are sent to the guest with
`/` separators, which `sshd` accepts on both operating systems.

| Operation | Windows guest | Linux guest |
|---|---|---|
| `upload` / `download` (file and directory) | supported; recursive trees keep spaces and non-ASCII names | unchanged |
| `create_dir` / `create_dir_all` / `exists` / `metadata` / `read` / `read_to_string` / `write` | supported | unchanged |
| `read_dir` / `remove_file` / `remove_dir_all` / `rename` | supported (`remove_dir_all` deletes the tree) | unchanged |
| `copy` | PowerShell `Copy-Item -LiteralPath ... -Destination ...`; never `cp` | `cp -p --` as before |
| `hard_link` | unsupported: returns an error | unchanged |
| `read_link` | unsupported: returns an error | unchanged |
| `set_permissions` | unsupported: Windows uses ACLs, not POSIX mode bits | unchanged |

Path rules for Windows guests:

- A drive letter is required (`C:\Users\qlean`); drive-relative (`C:foo`), root-relative
  (`\Users\qlean`) and bare names are rejected with an actionable error.
- `..` components are rejected, and every joined child is validated again, so a relative
  walk cannot escape the directory being uploaded or downloaded.
- Names Windows cannot store are rejected: `<>:"|?*`, control characters, trailing space
  or dot, and reserved device names (`CON`, `NUL`, `COM1`, `LPT1`, ...).
- UNC (`\\server\share`) and device (`\\?\`, `\\.\`) paths are rejected rather
  than guessed at.
- Symlinks are never silently skipped: uploading a tree that contains one, or downloading
  one, fails with an error naming the path. This applies to Linux guests too, where the
  link is recreated and a failure is reported.

### Getting Started

Add the dependency to your `Cargo.toml`:

```toml
[dev-dependencies]
qlean = "0.3"
tokio = { version = "1", features = ["full"] }
tracing-indicatif = "0.3"
tracing-subscriber = { version = "0.3", features = ["env-filter", "local-time"] }
```

Qlean uses [`tracing`](https://docs.rs/tracing) and [`indicatif`](https://docs.rs/indicatif) for structured logs and progress bars (for example while downloading images). To see that output in your own tests, add `tracing-indicatif` and `tracing-subscriber` as above and install a global subscriber once per process. A helper guarded with `std::sync::Once` works well when many tests share the same setup:

```rust
use std::sync::Once;

use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{
    EnvFilter, fmt::time::LocalTime, layer::SubscriberExt, util::SubscriberInitExt,
};

static INIT: Once = Once::new();

pub fn init_tracing() {
    INIT.call_once(|| {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,qlean=info"));
        let indicatif_layer = IndicatifLayer::new();
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_timer(LocalTime::rfc_3339())
                    .with_writer(indicatif_layer.get_stderr_writer()),
            )
            .with(indicatif_layer)
            .try_init()
            .ok();
    });
}
```

Call `init_tracing()` at the start of each test (or from a shared test harness). Adjust verbosity with `RUST_LOG`, for example `RUST_LOG=debug,qlean=trace`.

### Basic Example

A minimal single-VM test:

```rust
use anyhow::Result;
use qlean::{Image, ImageConfig, MachineConfig, with_machine};

#[tokio::test]
async fn test_with_vm() -> Result<()> {
    // Create VM image and config
    let image = Image::new(ImageConfig::default()).await?;
    let config = MachineConfig::default();

    // Execute tests in the virtual machine
    with_machine(&image, &config, |vm| {
        Box::pin(async {
            // Execute a command
            let result = vm.exec("whoami").await?;
            assert!(result.status.success());
            assert_eq!(str::from_utf8(&result.stdout)?.trim(), "root");
            
            Ok(())
        })
    })
    .await?;

    Ok(())
}
```

A distributed test with two VMs on the same virtual network:

```rust
use anyhow::Result;
use qlean::{Image, ImageConfig, MachineConfig, with_pool};

#[tokio::test]
async fn test_ping() -> Result<()> {
    with_pool(|pool| {
        Box::pin(async {
            // Create VM image and config
            let image = Image::new(ImageConfig::default()).await?;
            let config = MachineConfig::default();

            // Add machines to the pool and initialize them concurrently
            pool.add("alice", &image, &config).await?;
            pool.add("bob", &image, &config).await?;
            pool.init_all().await?;

            // Get mutable references to both machines by name
            let mut alice = pool.get("alice").await.expect("Alice machine not found");
            let mut bob = pool.get("bob").await.expect("Bob machine not found");

            // Test ping from Alice to Bob and vice versa
            let alice_ip = alice.get_ip().await?;
            let result = bob.exec(format!("ping -c 4 {}", alice_ip)).await?;
            assert!(result.status.success());
            let bob_ip = bob.get_ip().await?;
            let result = alice.exec(format!("ping -c 4 {}", bob_ip)).await?;
            assert!(result.status.success());

            Ok(())
        })
    })
    .await?;

    Ok(())
}
```

More examples live in the [tests](tests) directory.

## Network Configuration

Qlean uses a dedicated libvirt virtual network for isolated, reproducible connectivity between test VMs. The default definition is written to `~/.local/share/qlean/network.xml`:

```xml
<network>
  <name>qlean</name>
  <bridge name='qlbr0'/>
  <forward mode="nat"/>
  <ip address='192.168.221.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.221.2' end='192.168.221.254'/>
    </dhcp>
  </ip>
</network>
```

This defines a **NAT** network named `qlean` in libvirt, backed by the Linux bridge `qlbr0` at `192.168.221.1`. DHCP hands out addresses in `192.168.221.2`–`192.168.221.254` on the `192.168.221.0/24` subnet so VMs can reach each other, the host, and the outside world through NAT.

> [!NOTE]
> If `192.168.221.0/24` conflicts with your LAN, change the IP range in that file, but leave `<name>qlean</name>` and `<bridge name='qlbr0'/>` as they are—Qlean expects those identifiers.

## API Reference

### Top-Level Interface

- `is_kvm_available()` - Check if KVM is available on the host.
- `with_machine(image, config, f)` — Run an async closure with one VM; initializes on entry and shuts down on exit.
- `with_pool(f)` — Run an async closure with a `MachinePool`; shuts down all pool members on exit.

- `ImageConfig` - Configuration for a virtual machine image.

  ```rust
  pub struct ImageConfig {
    /// Guest operating system family, defaults to `GuestOs::Linux`.
    /// `GuestOs::Windows` requires an amd64 image plus an explicit
    /// `source` and `digest`; `distro` is ignored for Windows images.
    pub guest_os: GuestOs,
    /// Architecture of the image, defaults to `GuestArch::Amd64`.
    pub arch: GuestArch,
    /// Distribution of the image, defaults to `Distro::Debian`.
    pub distro: Distro,
    /// Source of the image, it can be a URL or a local file path. 
    /// If provided, the image will be fetched from the source and verified against the digest.
    pub source: Option<String>,
    /// Digest of the image, in the form of `sha256:<hex>` or `sha512:<hex>`. 
    /// It should be provided along with the source.
    pub digest: Option<String>,
    /// Whether to clear the image after use, defaults to `false`. 
    /// It is useful for custom images that are not expected to be used again.
    pub clear: bool,
  }
  ```

- `MachineConfig` - Configuration for a virtual machine.

  ```rust
  pub struct MachineConfig {
    /// Number of CPU cores, defaults to `2`.
    pub core: u32,
    /// Memory in MB, defaults to `4096`.
    pub mem: u32,
    /// Disk size in GB, defaults to `None`.
    /// If provided, the image will be resized to the specified size.
    pub disk: Option<u32>,
    /// Whether to clear the runtime directory after use, defaults to `true`.
    pub clear: bool,
    /// Timeout in seconds for SSH over vsock to wait during launch, 
    /// defaults to `180` with KVM and `300` under TCG.
    pub ssh_timeout: Option<u64>,
  }
  ```

### Guest OS and Image Validation

`GuestOs::Linux` is the default and keeps the existing built-in cloud image catalog
and cloud-init deployment. `GuestOs::Windows` is an explicit opt-in that requires:

- `arch = GuestArch::Amd64` (no other guest architecture is supported),
- an explicit `source` and `digest` — there is no built-in Windows image catalog,
  so an omitted pair is an error instead of a silent fallback to a Linux image.

Windows images use their own `windows-` cache namespace, and cached image metadata
records `guest_os`: metadata written before this field existed defaults to `Linux`,
and a cache entry whose recorded OS does not match the request is rejected instead
of being handed to the wrong guest.

> **Status:** Windows guest support is implemented on `main` but not released or
> supported yet. The `GuestOs` dimension, OVMF/TPM lifecycle, first-boot deployment,
> transport, `exec`, `get_ip` and file semantics are all in the tree, but the plan's
> core acceptance needs real Windows KVM smoke evidence that has not been recorded
> yet, so the support matrix below still lists Linux only and 0.4.0 is unpublished.

### Image Interface

- `Image::new(config)` - Create a new image with specified configuration.
- `Image::guest_os()` - Guest operating system family of the image.

### Machine Core Interface

- `Machine::new(image, config)` - Create a new machine instance.
- `Machine::init()` - Initialize the machine (first boot with cloud-init).
- `Machine::spawn()` - Start the machine (normal boot).
- `Machine::exec(command)` - Execute a command in the VM and return the output.
- `Machine::shutdown()` - Gracefully shutdown the virtual machine.
- `Machine::upload(src, dst)` - Upload a file or directory to the VM.
- `Machine::download(src, dst)` - Download a file or directory from the VM.
- `Machine::get_ip()` - Get the IP address of the VM.
- `Machine::is_running()` - Check if the VM is currently running.
- `Machine::guest_os()` - Guest operating system family of the machine's image (single source of truth for OS-dependent behavior).
- `Machine::open_interactive_shell(cols, rows)` - Open a dedicated interactive SSH shell (PTY) over a new vsock session. Does not block the management SSH session used by `exec` and upload. Requires the machine to already be running.

### Interactive Shell

For tooling that needs a terminal session (for example a web-based console), use `InteractiveShell` on a dedicated vsock SSH connection:

```rust
let shell = machine.open_interactive_shell(80, 24).await?;
shell.write(b"ls\n").await?;
while let Some(output) = shell.read_chunk().await? {
    // handle PTY output (stdout + stderr merged)
}
shell.resize(120, 40).await?;
shell.close().await?;
```

For concurrent read/write (WebSocket bridges, `tokio::select!`), split the shell:

```rust
let (mut reader, writer) = shell.split();
// reader.read_chunk() + writer.write() / resize() in select!
writer.close(reader).await?;
```

- `InteractiveShell::write(data)` - Send bytes to shell stdin.
- `InteractiveShell::read_chunk()` - Read the next output chunk; returns `None` when the shell exits.
- `InteractiveShell::resize(cols, rows)` - Resize the remote PTY.
- `InteractiveShell::close()` - Close the shell and its dedicated SSH session.
- `InteractiveShell::split()` - Split into reader/writer halves for concurrent I/O.

### Keep-alive / long-running VMs

By default, Qlean waits for the QEMU process until it exits (no wall-clock limit), so keep-alive workloads are not cut off after a fixed duration. Optional `QLEAN_QEMU_TIMEOUT_SECS` (positive integer) enables a bounded wait for tests; on timeout QEMU is killed before SSH operations are cancelled.

### Machine Pool Interface

- `MachinePool::new()` - Create a new, empty machine pool.
- `MachinePool::add(name, image, config)` - Add a new machine instance to the pool.
- `MachinePool::get(name)` - Get a machine instance by the name.
- `MachinePool::init_all()` - Initialize all machines in the pool concurrently.
- `MachinePool::spawn_all()` - Spawn all machines in the pool concurrently.
- `MachinePool::shutdown_all()` - Shutdown all machines in the pool concurrently.

### std::fs Compatible Interface

The following methods provide filesystem operations compatible with `std::fs` semantics:

- `Machine::copy(from, to)` - Copy a file within the VM.
- `Machine::create_dir(path)` - Create a directory.
- `Machine::create_dir_all(path)` - Create a directory and all missing parent directories.
- `Machine::exists(path)` - Check if a path exists.
- `Machine::hard_link(src, dst)` - Create a hard link.
- `Machine::metadata(path)` - Get file/directory metadata.
- `Machine::read(path)` - Read file contents as bytes.
- `Machine::read_dir(path)` - Read directory entries.
- `Machine::read_link(path)` - Read symbolic link target.
- `Machine::read_to_string(path)` - Read file contents as string.
- `Machine::remove_dir_all(path)` - Remove a directory after removing all its contents.
- `Machine::remove_file(path)` - Remove a file.
- `Machine::rename(from, to)` - Rename or move a file/directory.
- `Machine::set_permissions(path, perm)` - Set file/directory permissions.
- `Machine::write(path, contents)` - Write bytes to a file.

## Migration

### 0.3.x → 0.4.0

`ImageConfig` gained a `guest_os` field. `ImageConfig` is a public struct with public
fields, so struct-literal construction stops compiling:

```rust
// 0.3.x
let image = Image::new(ImageConfig {
    arch: GuestArch::Amd64,
    distro: Distro::Debian,
    source: None,
    digest: None,
    clear: false,
});

// 0.4.0
let image = Image::new(ImageConfig {
    arch: GuestArch::Amd64,
    distro: Distro::Debian,
    ..ImageConfig::default()
});

// or, avoiding literals entirely
let image = Image::new(
    ImageConfig::default()
        .with_distro(Distro::Debian)
        .with_guest_os(GuestOs::Linux),
);
```

`ImageConfig::default()`, the builder methods and the Linux runtime behavior are
unchanged; the break is source-level only. This release is a `0.x` minor bump
because the change cannot be expressed as a non-breaking addition.

## License

This project is licensed under the [MIT license](LICENSE).
