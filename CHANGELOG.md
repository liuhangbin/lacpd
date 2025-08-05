# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2025-08-05

### Fixed
- Fixed daemon mode logging issue where DEBUG level logs were not written to log file
- Fixed LACP negotiation with Linux 802.3ad bond
- Fixed PyInstaller packaging issue with fcntl module in daemon mode
- Fixed LACP packet reception issue by adding promiscuous mode support

## [0.1.1] - 2025-08-04

### Added
- `--log-file` parameter to save logs to specified file
- `--inject` parameter for automatic LACP state injection
  - Supports bit string (ATG), hexadecimal (0x40), and decimal (64) formats
  - Can target Actor (A) and Partner (P) states
  - Supports multiple inject rules
  - Format: "CONDITION -> TARGET" (e.g., "A:ATG|P:AT -> A:AT")
- `--exit-after-inject` parameter for automatic program termination
- Enhanced logging with partner state information in LACPDU reception
- Comprehensive test suite for inject functionality

## [0.1.0] - 2025-08-01

### Added
- Initial release of LACP Daemon
- Complete LACP (Link Aggregation Control Protocol) implementation
- Support for active and passive LACP modes
- Fast and slow rate modes (1s and 30s intervals)
- Network namespace support for Linux
- Real-time status query and monitoring
- Daemon mode for background operation
- JSON output support for structured data
- Comprehensive test suite
- Build system with PyInstaller support
- Development tools integration (black, ruff, mypy, pytest)

### Technical Details
- Python 3.12+ compatibility
- Type annotations throughout codebase
- Comprehensive error handling
- Cross-platform build support
- CI/CD integration with GitHub Actions
