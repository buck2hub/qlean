# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-01-31

### Fixed

- Use `qemu:///system` URI to enable bridge creation for proper network setup

## [0.2.1] - 2026-01-29

### Added

- Fallback to TCG (Tiny Code Generator) when KVM is unavailable, enabling execution on systems without hardware virtualization support

[Unreleased]: https://github.com/buck2hub/qlean/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/buck2hub/qlean/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/buck2hub/qlean/releases/tag/v0.2.1
