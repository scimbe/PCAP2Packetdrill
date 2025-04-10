"""
Base protocol handler interface.

This module defines the abstract base class for all protocol handlers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Any

from scapy.all import Packet


class ProtocolHandler(ABC):
    """Abstract base class for protocol handlers."""

    @abstractmethod
    def extract_packet_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Extract relevant information from a packet.

        Args:
            packet: The packet to extract information from

        Returns:
            A dictionary with packet information or None if the packet 
            should be ignored
        """
        pass

    @abstractmethod
    def format_packet(self, packet_info: Dict[str, Any]) -> str:
        """
        Format packet information as a packetdrill command.

        Args:
            packet_info: The packet information to format

        Returns:
            Packetdrill command string
        """
        pass

    @abstractmethod
    def identify_endpoints(self, packets_info: List[Dict[str, Any]]) -> Tuple[str, int, str, int]:
        """
        Identify client and server endpoints from a list of packets.

        Args:
            packets_info: List of packet information dictionaries

        Returns:
            Tuple of (client_ip, client_port, server_ip, server_port)
        """
        pass
