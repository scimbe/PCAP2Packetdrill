# PCAP2Packetdrill Examples

This directory contains example PCAP files and their corresponding Packetdrill scripts.

## Usage

To run these examples, first install the PCAP2Packetdrill tool:

```bash
pip install pcap2packetdrill
```

Then, convert a PCAP file to a Packetdrill script:

```bash
pcap2packetdrill examples/tcp_handshake.pcap -o examples/tcp_handshake.pkt
```

## Examples

### TCP Handshake

`tcp_handshake.pcap` - A simple TCP three-way handshake

To generate the Packetdrill script:

```bash
pcap2packetdrill examples/tcp_handshake.pcap -p tcp -o examples/tcp_handshake.pkt
```

### UDP DNS Query

`udp_dns.pcap` - A UDP DNS query and response

To generate the Packetdrill script:

```bash
pcap2packetdrill examples/udp_dns.pcap -p udp -o examples/udp_dns.pkt
```

### SCTP Association Setup

`sctp_setup.pcap` - An SCTP association setup

To generate the Packetdrill script:

```bash
pcap2packetdrill examples/sctp_setup.pcap -p sctp -o examples/sctp_setup.pkt
```

## Adding Your Own Examples

You can add your own PCAP files to this directory and generate Packetdrill scripts from them. If you have interesting examples that demonstrate specific protocol behaviors, consider contributing them back to the project!
