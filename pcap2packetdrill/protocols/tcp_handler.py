"""
TCP protocol handler module.

This module provides functionality to process TCP packets and convert them to packetdrill format.
"""

from typing import Dict, List, Optional, Tuple, Any

from scapy.all import Packet
from scapy.layers.inet import IP, TCP

from pcap2packetdrill.protocols.base import ProtocolHandler


class TCPHandler(ProtocolHandler):
    """Handler for TCP protocol packets."""

    def extract_packet_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract information from a TCP packet."""
        if not (IP in packet and TCP in packet):
            return None

        ip = packet[IP]
        tcp = packet[TCP]

        info = {
            "timestamp": float(packet.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": tcp.flags,
            "win": tcp.window,
            "payload": bytes(tcp.payload) if tcp.payload else b"",
            "options": tcp.options,
        }

        return info

    def format_packet(self, packet_info: Dict[str, Any]) -> str:
        """Format TCP packet information as a packetdrill command."""
        direction = "-->"
        flags_str = self._format_tcp_flags(packet_info["flags"])
        
        options_str = ""
        if packet_info["options"]:
            options_str = ", " + self._format_tcp_options(packet_info["options"])

        payload_str = ""
        if packet_info["payload"]:
            hex_payload = packet_info["payload"].hex()
            payload_str = f', {"0x{hex_payload}"}'

        return (
            f'{packet_info["timestamp"]:.6f} '
            f'{packet_info["src_ip"]}:{packet_info["src_port"]} {direction} '
            f'{packet_info["dst_ip"]}:{packet_info["dst_port"]} '
            f'tcp {flags_str} seq {packet_info["seq"]} ack {packet_info["ack"]} '
            f'win {packet_info["win"]}{options_str}{payload_str}'
        )

    def identify_endpoints(self, packets_info: List[Dict[str, Any]]) -> Tuple[str, int, str, int]:
        """Identify client and server endpoints from TCP packets."""
        # Find SYN packet to identify client
        for packet in packets_info:
            if packet["flags"] & 0x02:  # SYN flag
                return (
                    packet["src_ip"],
                    packet["src_port"],
                    packet["dst_ip"],
                    packet["dst_port"],
                )
                
        # If no SYN packet is found, use the first packet's source as client
        if packets_info:
            return (
                packets_info[0]["src_ip"],
                packets_info[0]["src_port"],
                packets_info[0]["dst_ip"],
                packets_info[0]["dst_port"],
            )
            
        # Fallback
        return ("0.0.0.0", 0, "0.0.0.0", 0)

    @staticmethod
    def _format_tcp_flags(flags: int) -> str:
        """Format TCP flags as a string."""
        flag_map = {
            0x01: "F",  # FIN
            0x02: "S",  # SYN
            0x04: "R",  # RST
            0x08: "P",  # PSH
            0x10: "A",  # ACK
            0x20: "U",  # URG
            0x40: "E",  # ECE
            0x80: "C",  # CWR
        }
        
        result = []
        for bit, char in flag_map.items():
            if flags & bit:
                result.append(char)
                
        return "".join(result)

    @staticmethod
    def _format_tcp_options(options: List[Tuple[str, Any]]) -> str:
        """Format TCP options as a string."""
        result = []
        for opt_name, opt_val in options:
            if opt_name == "MSS":
                result.append(f"mss {opt_val}")
            elif opt_name == "SAckOK":
                result.append("sackOK")
            elif opt_name == "Timestamp":
                result.append(f"ts val {opt_val[0]} ecr {opt_val[1]}")
            elif opt_name == "WScale":
                result.append(f"wscale {opt_val}")
            # Add more options as needed
                
        return " ".join(result)
