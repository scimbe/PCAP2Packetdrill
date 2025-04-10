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
    
    def __init__(self):
        """Initialize the UDP handler."""
        super().__init__()
        self.client_ip = None
        self.client_port = None
        self.server_ip = None
        self.server_port = None

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
        # Determine packet direction (> for outgoing, < for incoming)
        if packet_info["src_ip"] == self.client_ip and packet_info["src_port"] == self.client_port:
            direction = ">"  # Outgoing (client to server)
        else:
            direction = "<"  # Incoming (server to client)
        
        # Format payload
        payload_len = len(packet_info["payload"]) if packet_info["payload"] else 0
        
        # Format payload content if needed
        payload_content = ""
        if packet_info["payload"]:
            # Format as hex or appropriate representation as needed by packetdrill
            hex_payload = packet_info["payload"].hex()
            payload_content = f' data {hex_payload}'
        
        # Format the packet information as a packetdrill command
        return (
            f'+{packet_info["timestamp"]:.6f} {direction} udp {payload_len}{payload_content}'
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
