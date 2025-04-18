"""
Protocol handlers for PCAP2Packetdrill.

This module defines the abstract protocol handler interface and
implementations for specific protocols (TCP, UDP, SCTP).
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Any

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP

# Try to import SCTP, but provide a fallback if not available
try:
    from scapy.contrib.sctp import SCTP
except ImportError:
    # Create a dummy SCTP class for type checking
    class SCTP:
        """Dummy SCTP class for when scapy.contrib.sctp is not available."""
        pass


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


class SCTPHandler(ProtocolHandler):
    """Handler for SCTP protocol packets."""

    def extract_packet_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract information from a SCTP packet."""
        try:
            # Safely check if this is an SCTP packet using hasattr and __contains__
            has_ip = hasattr(packet, '__contains__') and IP in packet
            has_sctp = hasattr(packet, '__contains__') and SCTP in packet
            
            if not (has_ip and has_sctp):
                return None
            
            # Get IP layer
            ip = packet[IP]
            # Get SCTP layer
            sctp = packet[SCTP]
            
            # Extract basic information
            info = {
                "timestamp": float(packet.time),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_port": sctp.sport,
                "dst_port": sctp.dport,
                "tag": getattr(sctp, "tag", 0),
                "chunks": getattr(sctp, "chunks", []),
            }
            
            return info
        except (AttributeError, TypeError, IndexError) as e:
            # Log the error and return None on any exception
            return None

    def format_packet(self, packet_info: Dict[str, Any]) -> str:
        """Format SCTP packet information as a packetdrill command."""
        direction = "-->"
        
        chunks_str = self._format_sctp_chunks(packet_info.get("chunks", []))

        return (
            f'{packet_info["timestamp"]:.6f} '
            f'{packet_info["src_ip"]}:{packet_info["src_port"]} {direction} '
            f'{packet_info["dst_ip"]}:{packet_info["dst_port"]} '
            f'sctp tag {packet_info.get("tag", 0)}{chunks_str}'
        )

    def identify_endpoints(self, packets_info: List[Dict[str, Any]]) -> Tuple[str, int, str, int]:
        """Identify client and server endpoints from SCTP packets."""
        # Find INIT chunk to identify client
        for packet in packets_info:
            for chunk in packet.get("chunks", []):
                if chunk.get("type") == 1:  # INIT chunk
                    return (
                        packet["src_ip"],
                        packet["src_port"],
                        packet["dst_ip"],
                        packet["dst_port"],
                    )
                    
        # If no INIT chunk is found, use the first packet's source as client
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
    def _format_sctp_chunks(chunks: List[Dict[str, Any]]) -> str:
        """Format SCTP chunks as a string."""
        if not chunks:
            return ""
            
        result = []
        for chunk in chunks:
            if isinstance(chunk, dict):
                chunk_type = chunk.get("type", 0)
                
                # INIT
                if chunk_type == 1:
                    result.append(f'INIT[flgs=0, tag={chunk.get("init_tag", 0)}, '
                                f'a_rwnd={chunk.get("a_rwnd", 0)}, '
                                f'os={chunk.get("out_streams", 0)}, '
                                f'is={chunk.get("in_streams", 0)}, '
                                f'tsn={chunk.get("init_tsn", 0)}]')
                # INIT ACK
                elif chunk_type == 2:
                    result.append(f'INIT_ACK[flgs=0, tag={chunk.get("init_tag", 0)}, '
                                f'a_rwnd={chunk.get("a_rwnd", 0)}, '
                                f'os={chunk.get("out_streams", 0)}, '
                                f'is={chunk.get("in_streams", 0)}, '
                                f'tsn={chunk.get("init_tsn", 0)}]')
                # COOKIE ECHO
                elif chunk_type == 10:
                    cookie = chunk.get("cookie", b"").hex() if hasattr(chunk.get("cookie", b""), "hex") else "1234"
                    result.append(f'COOKIE_ECHO[flgs=0, len={len(cookie)//2}, val=0x{cookie}]')
                # COOKIE ACK
                elif chunk_type == 11:
                    result.append("COOKIE_ACK[flgs=0]")
                # DATA
                elif chunk_type == 0:
                    data = chunk.get("data", b"").hex() if hasattr(chunk.get("data", b""), "hex") else ""
                    result.append(f'DATA[flgs={chunk.get("flags", 0)}, '
                                f'len={len(data)//2}, '
                                f'tsn={chunk.get("tsn", 0)}, '
                                f'sid={chunk.get("stream_id", 0)}, '
                                f'ssn={chunk.get("stream_seq", 0)}, '
                                f'ppid={chunk.get("proto_id", 0)}, '
                                f'val=0x{data}]')
                # SACK
                elif chunk_type == 3:
                    result.append(f'SACK[flgs=0, cum_tsn={chunk.get("cum_tsn", 0)}, '
                                f'a_rwnd={chunk.get("a_rwnd", 0)}]')
                # HEARTBEAT
                elif chunk_type == 4:
                    info = chunk.get("info", b"").hex() if hasattr(chunk.get("info", b""), "hex") else ""
                    result.append(f'HEARTBEAT[flgs=0, info=0x{info}]')
                # HEARTBEAT ACK
                elif chunk_type == 5:
                    info = chunk.get("info", b"").hex() if hasattr(chunk.get("info", b""), "hex") else ""
                    result.append(f'HEARTBEAT_ACK[flgs=0, info=0x{info}]')
                # ABORT
                elif chunk_type == 6:
                    result.append(f'ABORT[flgs={chunk.get("flags", 0)}]')
                # SHUTDOWN
                elif chunk_type == 7:
                    result.append(f'SHUTDOWN[flgs=0, cum_tsn={chunk.get("cum_tsn", 0)}]')
                # SHUTDOWN ACK
                elif chunk_type == 8:
                    result.append("SHUTDOWN_ACK[flgs=0]")
                # ERROR
                elif chunk_type == 9:
                    result.append("ERROR[flgs=0]")
                # SHUTDOWN COMPLETE
                elif chunk_type == 14:
                    result.append(f'SHUTDOWN_COMPLETE[flgs={chunk.get("flags", 0)}]')
                # Unknown chunk type
                else:
                    result.append(f'CHUNK[type={chunk_type}, flgs={chunk.get("flags", 0)}]')
            else:
                # Handle non-dict chunk (e.g., object with attributes)
                chunk_type = getattr(chunk, "type", 0)
                if chunk_type == 1:  # INIT
                    result.append(f'INIT[flgs=0, tag={getattr(chunk, "init_tag", 0)}, '
                                f'a_rwnd={getattr(chunk, "a_rwnd", 0)}, '
                                f'os={getattr(chunk, "out_streams", 0)}, '
                                f'is={getattr(chunk, "in_streams", 0)}, '
                                f'tsn={getattr(chunk, "init_tsn", 0)}]')
                else:
                    # Generic handler for other chunk types
                    result.append(f'CHUNK[type={chunk_type}]')
                
        return ", " + ", ".join(result) if result else ""


# Register supported protocols
SUPPORTED_PROTOCOLS = {
    "tcp": TCPHandler(),
    "udp": UDPHandler(),
    "sctp": SCTPHandler(),
}
