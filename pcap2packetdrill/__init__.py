"""
PCAP2Packetdrill: Convert PCAP files to Packetdrill test scripts.

This tool helps network engineers and developers convert packet captures into 
reproducible Packetdrill test scripts for UDP, TCP, and SCTP protocols.
"""

from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS
from pcap2packetdrill.flow import FlowAnalyzer
from pcap2packetdrill.generator import ReplayManager

__version__ = "0.2.0"

__all__ = [
    'SUPPORTED_PROTOCOLS',
    'FlowAnalyzer',
    'ReplayManager',
]
