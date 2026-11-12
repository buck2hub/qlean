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
- Host prerequisite checks for Windows guests (KVM, OVMF, `swtpm`) that report every missing prerequisite in one actionable error, with `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS`/`QLEAN_SWTPM` overrides
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

### Changed

- Cached image metadata records `guest_os`; legacy metadata without the field deserializes as `Linux`, and a cache entry recorded for a different guest OS is rejected with an actionable error
- Windows image cache entries use a `windows-` name prefix so they can never share a cache slot with a Linux image
- Windows guests reject TCG: a launch without KVM acceleration now fails with an actionable error instead of silently emulating
- `Machine::open_interactive_shell` returns an actionable error for `GuestOs::Windows` instead of attempting a vsock shell

### Fixed

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
