# PCAP2Packetdrill

[![Python Tests](https://github.com/scimbe/PCAP2Packetdrill/actions/workflows/python-test.yml/badge.svg)](https://github.com/scimbe/PCAP2Packetdrill/actions/workflows/python-test.yml)

A tool for converting PCAP (packet capture) files into Packetdrill test scripts for UDP, TCP, and SCTP protocols.

## Overview

PCAP2Packetdrill helps network engineers and developers convert packet captures into reproducible Packetdrill test scripts. This enables easier debugging, testing, and validation of network protocol implementations.

### Supported Protocols
- TCP (Transmission Control Protocol)
- UDP (User Datagram Protocol)
- SCTP (Stream Control Transmission Protocol)

## Features

- Convert PCAP files to Packetdrill test scripts
- Support for multiple protocols (TCP, UDP, SCTP)
- Automatic flow analysis and test case generation
- Automatic detection of pre- and post-conditions
- Filter packets based on connection/flow
- Configurable timestamp handling
- Automatic identification of client/server roles
- Customizable template system for output scripts

## Installation

### Prerequisites
- Python 3.8 or higher
- libpcap development files
- pip (Python package installer)

### Installing from PyPI

```bash
pip install pcap2packetdrill
```

### Installing from Source

```bash
git clone https://github.com/scimbe/PCAP2Packetdrill.git
cd PCAP2Packetdrill
pip install -e .
```

## Usage

### Basic Usage

Convert a PCAP file to a single Packetdrill script:

```bash
pcap2packetdrill input.pcap -o output_script.pkt
```

Specify a protocol:

```bash
pcap2packetdrill input.pcap -p tcp -o tcp_test.pkt
```

### Automatic Analysis Mode

Analyze a PCAP file and generate test scripts for all detected protocols:

```bash
pcap2packetdrill input.pcap --auto-analyze
```

This will:
1. Analyze the PCAP file structure
2. Identify all protocols present (TCP, UDP, SCTP)
3. Find significant flows for each protocol
4. Determine appropriate pre- and post-conditions
5. Generate separate test scripts for each protocol

Specify an output directory:

```bash
pcap2packetdrill input.pcap --auto-analyze --output-dir ./test_scripts
```

### Complete Options

For all available options:

```bash
pcap2packetdrill --help
```

Key options include:
- `--auto-analyze`: Automatically analyze the PCAP and generate tests for all protocols
- `--client-ip`, `--server-ip`: Specify endpoints (auto-detected by default)
- `--client-port`, `--server-port`: Specify ports (auto-detected by default)
- `--relative-time/--absolute-time`: Use relative or absolute timestamps
- `--template`: Use a custom template
- `--output-dir`: Output directory for auto-analysis mode
- `--debug`: Show detailed logs during conversion

## Examples

See the [examples](./examples) directory for sample PCAP files and corresponding Packetdrill scripts.

### Example: Automatic Analysis

```bash
# Analyze a PCAP file and generate tests for all protocols
pcap2packetdrill capture.pcap --auto-analyze --output-dir ./tests

# This may generate:
# - ./tests/capture_tcp.pkt
# - ./tests/capture_udp.pkt
# - ./tests/capture_sctp.pkt
```

## Development

### Setup Development Environment

```bash
git clone https://github.com/scimbe/PCAP2Packetdrill.git
cd PCAP2Packetdrill
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Packetdrill](https://github.com/google/packetdrill) - The network stack testing tool
- [Scapy](https://scapy.net/) - The Python packet manipulation library used for PCAP parsing

## Author

Martin Becke