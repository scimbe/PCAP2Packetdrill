"""
Protocol handlers for PCAP2Packetdrill.

This module exports the protocol handler for TCP protocol.
"""

from pcap2packetdrill.protocols.base import ProtocolHandler
from pcap2packetdrill.protocols.tcp_handler import TCPHandler

# Register supported protocols
SUPPORTED_PROTOCOLS = {
    "tcp": TCPHandler(),
}

__all__ = [
    'ProtocolHandler',
    'TCPHandler',
    'SUPPORTED_PROTOCOLS'
]
