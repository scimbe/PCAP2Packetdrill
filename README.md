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

Basic usage:

```bash
pcap2packetdrill input.pcap -o output_script.pkt
```

Specifying a protocol:

```bash
pcap2packetdrill input.pcap -p tcp -o tcp_test.pkt
```

For more options:

```bash
pcap2packetdrill --help
```

## Examples

See the [examples](./examples) directory for sample PCAP files and corresponding Packetdrill scripts.

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