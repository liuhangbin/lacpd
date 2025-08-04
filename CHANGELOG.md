# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--log-file` parameter to save log messages to specified file
  - Supports saving logs to any valid file path
  - Logs are written to both console and file when specified
  - Compatible with all existing command-line options
  - Useful for debugging and monitoring in production environments

### Changed
- Enhanced logging system to support dual output (console + file)
- Updated argument parser to include `--log-file` option
- Extended test coverage for new logging functionality

### Fixed
- No fixes in this release

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
- Development tools integration (black, flake8, mypy, pytest)

### Features
- LACP Actor implementation with full state machine
- LACPDU packet construction and parsing
- Ethernet frame handling
- Unix socket communication for status queries
- Process management and daemonization
- Network namespace isolation support
- Command-line interface with comprehensive options

### Technical Details
- Python 3.12+ compatibility
- Type annotations throughout codebase
- Comprehensive error handling
- Cross-platform build support
- CI/CD integration with GitHub Actions