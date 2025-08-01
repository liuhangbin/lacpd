# LACP Daemon

A Python daemon for simulating LACP (Link Aggregation Control Protocol) negotiation processes. It allows injection of custom LACP messages during negotiation, which is very useful for testing the robustness of LACP implementations.

> **Note**: This project was built with the assistance of [Cursor AI](https://cursor.sh).

## Features

- **Complete LACP Implementation**: Supports all core features of IEEE 802.3ad standard
- **Active/Passive Mode**: Supports both active and passive LACP modes
- **Rate Modes**: Supports fast (1-second interval) and slow (30-second interval) modes
- **Network Namespace Support**: Supports Linux network namespace isolation
- **Status Query**: Provides real-time status query and monitoring capabilities
- **Daemon Mode**: Supports background operation
- **JSON Output**: Supports structured data output

## Installation

### Install from Source

```bash
# Clone repository
git clone https://github.com/example/lacpd.git
cd lacpd

# Install development dependencies using uv
uv sync --dev

# Or install in development mode
uv pip install -e ".[dev]"

# After installation, add .venv/bin to PATH for direct lacpd command access
export PATH="$PWD/.venv/bin:$PATH"
```

### Build Standalone Binary

```bash
# Build release binary
make binary

# Build debug binary
make binary-debug

# The binary will be created at: dist/lacpd
# You can run it directly: ./dist/lacpd --help
```

### System Requirements

- Python 3.12+ (for development)
- uv (Python package manager)
- Linux operating system (requires network namespace support)
- Administrator privileges (for raw socket access)
- PyInstaller (for building standalone binary)

## Usage

### Basic Usage

```bash
# Using installed lacpd command
sudo lacpd -i eth0

# Using standalone binary
sudo ./dist/lacpd -i eth0

# Start on multiple interfaces
sudo lacpd -i eth0 -i eth1

# Run in daemon mode
sudo lacpd -i eth0 -d

# Use passive mode
sudo lacpd -i eth0 --passive

# Use slow rate mode
sudo lacpd -i eth0 --rate slow
```

### Status Query

```bash
# Query status of all LACP daemons
lacpd -s

# Query daemons in specific namespace
lacpd -s -n my_namespace

# Query status of specific interface
lacpd -s -i eth0

# JSON format output
lacpd -s -j

# Pretty-printed JSON output
lacpd -s -p
```

### Process Management

```bash
# Terminate all LACP daemons in current namespace
lacpd -k

# Terminate daemons in specific namespace
lacpd -k -n my_namespace
```

### Advanced Options

```bash
# Set log level
lacpd -i eth0 --log-level DEBUG

# Combine multiple options
sudo lacpd -i eth0 -i eth1 --passive --rate slow -d --log-level INFO
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | Network interface name (can be specified multiple times) | Required |
| `-s, --status` | Query status of running LACP daemons | - |
| `-k, --kill` | Terminate LACP daemons | - |
| `-d, --daemon` | Run in daemon mode | False |
| `--passive` | Use passive mode | False |
| `--rate` | LACP rate mode (fast/slow) | fast |
| `-n, --namespace` | Network namespace name | Current namespace |
| `-j, --json` | JSON format output | False |
| `-p, --pretty` | Pretty-printed JSON output | False |
| `--log-level` | Log level | INFO |

## Project Structure

```
lacpd/
├── src/
│   └── lacpd/
│       ├── __init__.py      # Package initialization
│       ├── main.py          # Main program entry point
│       ├── actor.py         # LACP Actor implementation
│       ├── packet.py        # LACP packet processing
│       └── utils.py         # Utility functions
├── tests/
│   ├── __init__.py
│   ├── test_main.py         # Main module tests
│   ├── test_packet.py       # Packet tests
│   ├── test_utils.py        # Utility tests
│   └── run_test.sh          # Integration test script
├── lacpd.spec               # PyInstaller specification
├── Makefile                 # Build and development tasks
├── README.md                # Project documentation
└── LICENSE                  # License
```

## Development

### Setting Up Development Environment

```bash
# Install development dependencies using uv
uv sync --dev

# Or create virtual environment manually
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install development dependencies
uv pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run specific tests
uv run pytest tests/test_packet.py

# Run integration tests (requires root privileges)
sudo bash tests/run_test.sh

# Generate coverage report
uv run pytest --cov=lacpd --cov-report=html
```

### Code Quality

```bash
# Code formatting
uv run black src/ tests/

# Code linting
uv run flake8 src/ tests/

# Type checking
uv run mypy src/

# Run all quality checks
uv run pre-commit run --all-files
```

## LACP Protocol Overview

LACP (Link Aggregation Control Protocol) is a protocol defined in the IEEE 802.3ad standard for automatic configuration and management of link aggregation groups.

### Main Components

1. **Actor**: Local port information
2. **Partner**: Remote port information
3. **Mux State Machine**: Multiplexing state machine
4. **Selection Logic**: Selection logic

### State Bits

- `ACTIVE`: Active mode
- `SHORT_TIMEOUT`: Short timeout
- `AGGREGATION`: Aggregation capability
- `SYNC`: Synchronization state
- `COLLECTING`: Collecting state
- `DISTRIBUTING`: Distributing state
- `DEFAULTED`: Default state
- `EXPIRED`: Expired state

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 code style
- Add appropriate type annotations
- Write tests for new features
- Update documentation

## License

This project is licensed under the GNU General Public License v3 or later (GPLv3+) - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

1. **Permission Error**: Ensure running with root privileges as raw socket access is required
2. **Interface Not Found**: Check if the network interface name is correct
3. **Namespace Issues**: Ensure the network namespace exists and you have permission to access it

### Debugging

```bash
# Enable debug logging
lacpd -i eth0 --log-level DEBUG

# Check system logs
journalctl -f

# Check network interface status
ip link show
```

## CI/CD

This project uses GitHub Actions for continuous integration and deployment:

- **CI**: Automatically runs tests, linting, and type checking on pull requests
- **CD**: Automatically builds and releases binaries for multiple platforms and architectures (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64) when a release is published

For detailed information about the CI/CD setup, see [`.github/workflows/README.md`](.github/workflows/README.md).

## Related Links

- [IEEE 802.3ad Standard](https://standards.ieee.org/standard/802_3ad-2000.html)
- [Linux Network Namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)