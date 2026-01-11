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

Before using Qlean, ensure that QEMU, guestfish, libguestfs-tools and some other utils are properly installed on your Linux host. You can verify the installation with the following commands:

```bash
qemu-system-x86_64 --version
qemu-img --version
guestfish --version
virt-copy-out --version
xorriso --version
sha256sum --version
sha512sum --version
```

### Getting Started

Add the dependency to your `Cargo.toml`:

```toml
[dev-dependencies]
qlean = "0.1"
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

For more examples, please refer to the [tests](tests) directory.

## API Reference

### Top-Level Interface

- `create_image(distro, name)` - Create or retrieve a VM image from the specified distribution
- `with_machine(image, config, f)` - Execute an async closure in a virtual machine with automatic resource cleanup
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
