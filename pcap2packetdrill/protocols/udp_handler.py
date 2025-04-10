"""
UDP protocol handler module.

This module provides functionality to process UDP packets and convert them to packetdrill format.
"""

from typing import Dict, List, Optional, Tuple, Any

from scapy.all import Packet
from scapy.layers.inet import IP, UDP

from pcap2packetdrill.protocols.base import ProtocolHandler


class UDPHandler(ProtocolHandler):
    """Handler for UDP protocol packets."""

    def extract_packet_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract information from a UDP packet."""
        if not (IP in packet and UDP in packet):
            return None

        ip = packet[IP]
        udp = packet[UDP]

        info = {
            "timestamp": float(packet.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "payload": bytes(udp.payload) if udp.payload else b"",
        }

        return info

    def format_packet(self, packet_info: Dict[str, Any]) -> str:
        """Format UDP packet information as a packetdrill command."""
        direction = "-->"
        
        payload_str = ""
        if packet_info["payload"]:
            hex_payload = packet_info["payload"].hex()
            payload_str = f', {"0x{hex_payload}"}'

        return (
            f'{packet_info["timestamp"]:.6f} '
            f'{packet_info["src_ip"]}:{packet_info["src_port"]} {direction} '
            f'{packet_info["dst_ip"]}:{packet_info["dst_port"]} '
            f'udp{payload_str}'
        )

    def identify_endpoints(self, packets_info: List[Dict[str, Any]]) -> Tuple[str, int, str, int]:
        """Identify client and server endpoints from UDP packets."""
        # For UDP we'll use a simple heuristic: the side that sent the first packet
        # is considered the client
        if packets_info:
            return (
                packets_info[0]["src_ip"],
                packets_info[0]["src_port"],
                packets_info[0]["dst_ip"],
                packets_info[0]["dst_port"],
            )
            
        # Fallback
        return ("0.0.0.0", 0, "0.0.0.0", 0)
