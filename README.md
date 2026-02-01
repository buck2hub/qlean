# Qlean

**Qlean** is a system-level isolation testing library based on QEMU/KVM, providing complete virtual machine isolation environments for Rust projects.

## Overview

Qlean provides a comprehensive testing solution for projects requiring system-level isolation by launching lightweight virtual machines during tests. It addresses two major challenges:

**1. Complete Resource Isolation**

Many projects require root privileges or direct manipulation of system-level resources. Traditional single-machine tests can easily crash the host system if tests fail. Qlean uses virtual machine isolation to completely isolate these operations within the VM, ensuring host system stability.

**2. Convenient Multi-Machine Testing**

For projects requiring multi-machine collaboration, Qlean provides a simple API that allows you to easily create and manage multiple VM instances in test code without complex infrastructure configuration.

## Key Features

- 🔒 **Complete Isolation**: Based on QEMU/KVM, providing full virtual machine isolation
- 🔄 **Multi-Machine Support**: Easily create and manage multiple virtual machines
- 🛡️ **RAII-style Interface**: Automatic resource management ensures VMs are properly cleaned up
- 📦 **Out-of-the-Box**: Automated image downloading and extraction, no manual configuration needed
- 🐧 **Linux Native**: Native support for Linux hosts with multiple Linux distributions

## Usage

### Host Setup

#### Install CLI utils

Before using Qlean, ensure that QEMU, guestfish, libvirt, libguestfs-tools and some other utils are properly installed on your Linux host. You can verify the installation with the following commands:

```bash
qemu-system-x86_64 --version
qemu-img --version
virsh --version
guestfish --version
virt-copy-out --version
xorriso --version
sha256sum --version
sha512sum --version
```

#### Configure qemu-bridge-helper

Qlean uses `qemu-bridge-helper` to manage networking for multiple virtual machines, so it requires proper configuration.

The `CAP_NET_ADMIN` capability needs to be set on for the default network helper:

```bash
sudo chmod u-s /usr/lib/qemu/qemu-bridge-helper
sudo setcap cap_net_admin+ep /usr/lib/qemu/qemu-bridge-helper
```

The ACL mechanism enforced by `qemu-bridge-helper` defaults to blacklisting all users, so the `qlbr0` bridge created by qlean must be explicitly allowed:

```bash
sudo mkdir -p /etc/qemu
sudo sh -c 'echo "allow qlbr0" > /etc/qemu/bridge.conf'
sudo chmod 644 /etc/qemu/bridge.conf
```

### Getting Started

Add the dependency to your `Cargo.toml`:

```toml
[dev-dependencies]
qlean = "0.2"
tokio = { version = "1", features = ["full"] }
```

### Basic Example

Here's a simple test example with single machine:

```rust
use anyhow::Result;
use qlean::{Distro, MachineConfig, create_image, with_machine};

#[tokio::test]
async fn test_with_vm() -> Result<()> {
    // Create VM image and config
    let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
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

The following is another example of a multi-machine test:

```rust
use anyhow::Result;
use qlean::{Distro, MachineConfig, create_image, with_pool};

#[tokio::test]
async fn test_ping() -> Result<()> {
    with_pool(|pool| {
        Box::pin(async {
            // Create VM image and config
            let image = create_image(Distro::Debian, "debian-13-generic-amd64").await?;
            let config = MachineConfig::default();

            // Add machines to the pool and initialize them concurrently
            pool.add("alice".to_string(), &image, &config).await?;
            pool.add("bob".to_string(), &image, &config).await?;
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

For more examples, please refer to the [tests](tests) directory.

## Network Configuration

Qlean uses a dedicated libvirt virtual network to provide isolated, reproducible networking for test VMs. The default network definition is stored at `~/.local/share/qlean/network.xml` as follows:

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

This configuration defines a **NAT-based** virtual network named `qlean` (used internally by libvirt) that creates a Linux bridge interface called `qlbr0`. The bridge is assigned the IP address `192.168.221.1` and serves as the gateway for a `/24` subnet (`192.168.221.0/24`). A built-in DHCP server automatically assigns IP addresses to virtual machines in the range `192.168.221.2` to `192.168.221.254`, enabling seamless network connectivity between the host, test VMs, and—via NAT—the external network.

> [!NOTE]
> If the `192.168.221.0/24` subnet conflicts with your local network, you may edit the configuration file to use a different IP range，but keep the `<name>qlean</name>` and `<bridge name='qlbr0'/>` unchanged to ensure compatibility with qlean's internal logic.

## API Reference

### Top-Level Interface

- `create_image(distro, name)` - Create or retrieve a VM image from the specified distribution
- `with_machine(image, config, f)` - Execute an async closure in a virtual machine with automatic resource cleanup
- `with_pool(f)` - Execute an async closure in a machine pool with automatic resource cleanup
- `MachineConfig` - Configuration for virtual machine resources (CPU, memory, disk)

  ```rust
  pub struct MachineConfig {
    pub core: u32,              // Number of CPU cores
    pub mem: u32,               // Memory size in MB
    pub disk: Option<u32>,      // Disk size in GB (optional)
    pub clear: bool,            // Clear resources after use
  }
  ```

### Machine Core Interface

- `Machine::new(image, config)` - Create a new machine instance
- `Machine::init()` - Initialize the machine (first boot with cloud-init)
- `Machine::spawn()` - Start the machine (normal boot)
- `Machine::exec(command)` - Execute a command in the VM and return the output
- `Machine::shutdown()` - Gracefully shutdown the virtual machine
- `Machine::upload(src, dst)` - Upload a file or directory to the VM
- `Machine::download(src, dst)` - Download a file or directory from the VM
- `Machine::get_ip()` - Get the IP address of the VM

### Machine Pool Interface

- `MachinePool::new()` - Create a new, empty machine pool
- `MachinePool::add(name, image, config)` - Add a new machine instance to the pool
- `MachinePool::get(name)` - Get a machine instance by the name
- `MachinePool::init_all()` - Initialize all machines in the pool concurrently
- `MachinePool::spawn_all()` - Spawn all machines in the pool concurrently
- `MachinePool::shutdown_all()` - Shutdown all machines in the pool concurrently

### std::fs Compatible Interface

The following methods provide filesystem operations compatible with `std::fs` semantics:

- `Machine::copy(from, to)` - Copy a file within the VM
- `Machine::create_dir(path)` - Create a directory
- `Machine::create_dir_all(path)` - Create a directory and all missing parent directories
- `Machine::exists(path)` - Check if a path exists
- `Machine::hard_link(src, dst)` - Create a hard link
- `Machine::metadata(path)` - Get file/directory metadata
- `Machine::read(path)` - Read file contents as bytes
- `Machine::read_dir(path)` - Read directory entries
- `Machine::read_link(path)` - Read symbolic link target
- `Machine::read_to_string(path)` - Read file contents as string
- `Machine::remove_dir_all(path)` - Remove a directory after removing all its contents
- `Machine::remove_file(path)` - Remove a file
- `Machine::rename(from, to)` - Rename or move a file/directory
- `Machine::set_permissions(path, perm)` - Set file/directory permissions
- `Machine::write(path, contents)` - Write bytes to a file

## License

This project is licensed under the [MIT license](LICENSE).
