"""
Protocol handlers for PCAP2Packetdrill.

This module exports the protocol handlers for TCP, UDP, and SCTP protocols.
"""

from pcap2packetdrill.protocols.base import ProtocolHandler
from pcap2packetdrill.protocols.tcp_handler import TCPHandler
from pcap2packetdrill.protocols.udp_handler import UDPHandler
from pcap2packetdrill.protocols.sctp_handler import SCTPHandler

# Register supported protocols
SUPPORTED_PROTOCOLS = {
    "tcp": TCPHandler(),
    "udp": UDPHandler(),
    "sctp": SCTPHandler(),
}

__all__ = [
    'ProtocolHandler',
    'TCPHandler',
    'UDPHandler',
    'SCTPHandler',
    'SUPPORTED_PROTOCOLS'
]
