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

### Image Interface

- `Image::new(config)` - Create a new image with specified configuration.

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

## License

This project is licensed under the [MIT license](LICENSE).
