# PCAP2Packetdrill (Work in Progress)

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
- Generate replay tests for complete TCP/SCTP connections
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

### SCTP Support

PCAP2Packetdrill supports SCTP protocol analysis, but requires Scapy version 2.5.0 or higher for full SCTP support. The tool includes fallback mechanisms to handle cases where the SCTP module is not available, but for complete SCTP functionality, we recommend:

```bash
pip install scapy>=2.5.0
```

## Usage

PCAP2Packetdrill provides two main commands:

```bash
# Show available commands
pcap2packetdrill --help

# Convert a PCAP file to a test script
pcap2packetdrill convert [OPTIONS] PCAP_FILE

# Generate replay test scripts from complete connections
pcap2packetdrill replay [OPTIONS] PCAP_FILE
```

### Basic Conversion

Convert a PCAP file to a single Packetdrill script:

```bash
pcap2packetdrill convert input.pcap -o output_script.pkt
```

Specify a protocol:

```bash
pcap2packetdrill convert input.pcap -p tcp -o tcp_test.pkt
```

### Automatic Analysis Mode

Analyze a PCAP file and generate test scripts for all detected protocols:

```bash
pcap2packetdrill convert input.pcap --auto-analyze
```

This will:
1. Analyze the PCAP file structure
2. Identify all protocols present (TCP, UDP, SCTP)
3. Find significant flows for each protocol
4. Determine appropriate pre- and post-conditions
5. Generate separate test scripts for each protocol

### Replay Test Generation

Generate a separate test script for each complete TCP connection and SCTP association:

```bash
pcap2packetdrill replay capture.pcap
```

This will:
1. Identify complete TCP connections (SYN → Data → FIN)
2. Identify complete SCTP associations (INIT → Data → SHUTDOWN)
3. Generate a separate, self-contained test script for each connection
4. Save them to the output directory with descriptive names

Specify an output directory:

```bash
pcap2packetdrill replay capture.pcap --output-dir ./replay_tests
```

### Complete Options

For all available options:

```bash
pcap2packetdrill convert --help
pcap2packetdrill replay --help
```

Key options for conversion include:
- `--auto-analyze`: Automatically analyze the PCAP and generate tests for all protocols
- `--client-ip`, `--server-ip`: Specify endpoints (auto-detected by default)
- `--client-port`, `--server-port`: Specify ports (auto-detected by default)
- `--relative-time/--absolute-time`: Use relative or absolute timestamps
- `--template`: Use a custom template
- `--output-dir`: Output directory for auto-analysis mode
- `--debug`: Show detailed logs during conversion

Key options for replay test generation:
- `--output-dir`: Directory to save generated test scripts
- `--template-dir`: Directory containing custom templates
- `--relative-time/--absolute-time`: Use relative or absolute timestamps
- `--debug`: Show detailed logs during test generation

## Examples

See the [examples](./examples) directory for sample PCAP files, corresponding Packetdrill scripts, and documentation:

- [Auto Analysis Example](./examples/auto_analysis_example.md) - Learn how to use the auto-analysis feature
- [Replay Test Example](./examples/replay_test_example.md) - Learn how to generate replay tests for complete connections

### Example: Replay Test Generation

```bash
# Generate replay tests for all complete connections in a PCAP file
pcap2packetdrill replay capture.pcap --output-dir ./replay_tests

# This may generate:
# - ./replay_tests/tcp_192_168_1_2_43210_to_192_168_1_1_80_cycle_1.pkt
# - ./replay_tests/tcp_192_168_1_2_43211_to_192_168_1_1_80_cycle_1.pkt
# - ./replay_tests/sctp_192_168_1_2_38745_to_192_168_1_1_8080_cycle_1.pkt
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
