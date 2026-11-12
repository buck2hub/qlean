# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `GuestOs` and `ImageConfig::guest_os` (default `GuestOs::Linux`) for describing the guest operating system family
- `ImageConfig::with_guest_os`, `Image::guest_os()` and `Machine::guest_os()` accessors
- Windows image validation: `GuestOs::Windows` requires `GuestArch::Amd64` plus an explicit `source` and `digest`
- Windows guests boot on OVMF UEFI firmware (`q35`, per-VM `ovmf_vars.fd` that survives restarts) and a per-VM TPM 2.0 device backed by `swtpm`
- Host prerequisite checks for Windows guests (KVM, OVMF, `swtpm`, `xorriso`) that report every missing prerequisite in one actionable error, with `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS`/`QLEAN_SWTPM` overrides
- README Windows host setup with minimum/recommended VM resources
- Windows first-boot deployment: a per-VM seed medium (`QLEANSEED`) carrying the client public key, a randomly generated per-VM SSH host key and `deploy.json`, attached only on `init` and deleted once the guest writes its deploy marker
- `Machine::ssh_host_key` exposes the per-VM Windows host key so the transport can pin it instead of trusting the first key seen
- Windows deployment budget of 900s (`MachineConfig::ssh_timeout` overrides) with an actionable timeout error, independent of the Linux SSH connect timeout
- README "Windows image contract" describing the required first-boot task, account and ACL rules
- Windows SSH transport over the libvirt NAT network: the guest address is resolved from its DHCP lease on the host before connecting, so `Machine::get_ip` never runs inside a Windows guest
- Pinned host keys for Windows SSH sessions: the key presented by the guest must match the per-VM key generated at deploy time, and certificates are rejected; Linux guests keep vsock trust-on-first-use
- `with_pool` no longer requires `/dev/vhost-vsock`, and `with_machine` requires it only for `GuestOs::Linux`
- README "Windows transport and security" describing address discovery, host key pinning, the Linux-only vsock requirement and pool isolation
- Windows `exec` semantics: command strings are passed verbatim to PowerShell (the image contract now requires OpenSSH's `DefaultShell` to be PowerShell), and exit codes outside `0..=255` are reported as errors instead of being truncated
- Empty and whitespace-only `exec` commands are rejected with an actionable error before an SSH request is sent
- README "Windows command execution" documenting the verbatim command contract, stream separation and exit-code rules
- `src/guest_path.rs`: a single `GuestPath` conversion layer for every remote SFTP entry point, validating Windows drive paths, root spelling, separators, spaces, non-ASCII names, `..` traversal, invalid characters, reserved device names, and rejecting UNC/device namespaces
- Windows file semantics: `upload`/`download` round-trip files and directory trees, `copy` uses PowerShell `Copy-Item -LiteralPath` instead of the POSIX `cp`, `remove_dir_all` deletes recursively, and `hard_link`/`read_link`/`set_permissions` return explicit unsupported errors
- Symbolic links are no longer skipped silently during `upload`/`download`: recreating a link that fails, or meeting a link that cannot be transferred, is now an error
- `Machine::get_ip` returns the transport address for Windows guests and, when it must be re-queried, runs PowerShell inside the guest and keeps only the address whose MAC matches that VM, erroring on a missing or ambiguous result instead of returning another VM's address

### Changed

- Cached image metadata records `guest_os`; legacy metadata without the field deserializes as `Linux`, and a cache entry recorded for a different guest OS is rejected with an actionable error
- Windows image cache entries use a `windows-` name prefix so they can never share a cache slot with a Linux image
- Windows guests reject TCG: a launch without KVM acceleration now fails with an actionable error instead of silently emulating
- A `secboot` OVMF code image paired with a vars template that carries no Microsoft keys (including via `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS`) is now refused with an actionable error instead of booting in Secure Boot setup mode, which Windows 11 rejects
- `Machine::open_interactive_shell` returns an actionable error for `GuestOs::Windows` instead of attempting a vsock shell

### Fixed

- Waiting for the Windows deployment marker treated a dropped session as "not deployed yet" and burned the whole 900s budget
- `MachinePool::init_all` failed on a Windows machine that had already deployed, and `spawn_all` booted a Windows guest before its deployment
- A launch that failed after QEMU started left `swtpm` and the pid behind, and a panicked SSH task detached QEMU entirely
- Windows DHCP lookup returned the first lease for a MAC, so a dual-stack network could hand a link-local IPv6 address that cannot be dialled
- `GuestPath::join` accepted an absolute child and silently made it relative on Linux, and reported `\\?\` device paths as UNC
- Host paths embedded in a comma-separated QEMU option (`-drive file=`, `-chardev path=`, the OVMF images and the `swtpm` socket) were interpolated verbatim, so a directory name containing a comma was read as extra key=value pairs instead of a file name; such paths now fail with an actionable error before QEMU starts
- Windows first-boot address discovery ran before the QEMU liveness check, so a VM that died right after starting waited out the whole deployment budget and blamed a missing DHCP lease
- Recursive directory creation tried to create (and stat) a Windows drive root such as `C:`, which is drive-relative and can fail
- A failed `init`/`spawn` left the cancel token behind, so retrying on the same `Machine` reported "already initialized"/"already spawned" for a VM that never started
- `Machine::copy` wrapped `Copy-Item` in `powershell -Command "..."` inside an already-PowerShell shell, so `$` in a Windows path was expanded and the copy silently targeted a different file
- The Windows host prerequisite check omitted `xorriso`, so a host without it passed the check and failed later while staging the seed medium
- Secure Boot paired a `secboot` code image with the plain (empty-key) vars template, which boots in setup mode; the Microsoft-enrolled `.ms`/`.secboot` templates are now preferred
- Windows guests were launched with `vhost-vsock-pci`, so a Windows VM needed `/dev/vhost-vsock` and the `vhost_vsock` module and failed to start without them; the device is now added only for Linux guests
- OVMF setup required the code image and vars template to be exactly the same size, which no stock firmware pair satisfies (a ~528 KiB vars template ships next to a multi-megabyte code image); only a vars template larger than the code image is now rejected
- The `swtpm` control socket was created with default permissions; it is now owner-only (`mode=0600`)
- A failed Windows first-boot deployment left the VM running with the seed medium (client public key and per-VM host private key) still attached; the launch path now closes the session, terminates QEMU, stops `swtpm` and clears the endpoint state
- A launch whose QEMU pid file could never be read now stops `swtpm` and waits a bounded time instead of returning while the TPM and a half-started VM remain
- A second `init` on an already-deployed Windows machine is rejected with an actionable error (use `spawn`), instead of booting without the consumed seed medium
- Windows first boot waited only for the 180s/300s Linux connect budget before giving up on `sshd`, so the 900s deployment budget could never be reached; `init` now waits within the deployment budget and later boots keep the connect budget
- `Machine::exec` reported every non-zero exit code as success: the SSH exit status was passed to `ExitStatus::from_raw` as if it were a wait status, so `status.code()` always returned `0`. Exit codes are now converted correctly, which is a behavior change for callers that relied on the previous (incorrect) `status.success()` result

### Migration

- `ImageConfig` gained a public field, so struct-literal construction must add `guest_os` or `..ImageConfig::default()`; builder chains and `ImageConfig::default()` behavior are unchanged (source-breaking `0.4.0` minor, see README Migration)

## [0.3.1] - 2026-07-28

### Added

- `InteractiveShell` API for dedicated vsock SSH+PTY interactive shells via `Machine::open_interactive_shell`
- `InteractiveShell::write`, `read_chunk`, `resize`, and `close` for bidirectional terminal I/O without blocking management SSH
- `InteractiveShell::split` into `InteractiveShellReader` / `InteractiveShellWriter` for concurrent PTY I/O (e.g. `tokio::select!`)


## [0.3.0] - 2026-07-01

### Changed

- SSH connectivity uses vhost-vsock only (no TCP fallback)

## [0.2.3] - 2026-02-12

### Added

- Multi-distro image support, custom image handling, and streaming hash computation

### Documentation

- Enhance README with multi-distro and custom image info
- Fix docs error

## [0.2.2] - 2026-01-31

### Fixed

- Use `qemu:///system` URI to enable bridge creation for proper network setup

## [0.2.1] - 2026-01-29

### Added

- Fallback to TCG (Tiny Code Generator) when KVM is unavailable, enabling execution on systems without hardware virtualization support

[Unreleased]: https://github.com/buck2hub/qlean/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/buck2hub/qlean/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/buck2hub/qlean/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/buck2hub/qlean/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/buck2hub/qlean/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/buck2hub/qlean/releases/tag/v0.2.1
