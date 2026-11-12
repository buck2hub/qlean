# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `GuestOs` and `ImageConfig::guest_os` (default `GuestOs::Linux`) for describing the guest operating system family
- `ImageConfig::with_guest_os`, `Image::guest_os()` and `Machine::guest_os()` accessors
- Windows image validation: `GuestOs::Windows` requires `GuestArch::Amd64` plus an explicit `source` and `digest`

### Changed

- Cached image metadata records `guest_os`; legacy metadata without the field deserializes as `Linux`, and a cache entry recorded for a different guest OS is rejected with an actionable error
- Windows image cache entries use a `windows-` name prefix so they can never share a cache slot with a Linux image

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
