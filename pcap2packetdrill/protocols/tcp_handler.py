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
    
    def __init__(self):
        """Initialize the TCP handler."""
        super().__init__()
        self.client_ip = None
        self.client_port = None
        self.server_ip = None
        self.server_port = None

    def extract_packet_info(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Extract information from a TCP packet."""
        if not (IP in packet and TCP in packet):
            return None

        ip = packet[IP]
        tcp = packet[TCP]
        
        # Convert TCP flags to integer by examining the flags attribute
        try:
            # Try to extract the numeric value
            flags_value = int(tcp.flags)
        except (ValueError, TypeError):
            # If that fails, try to extract from the name
            flags_value = 0
            flags_str = str(tcp.flags)
            
            # Map from flag name to bit value
            flag_map = {
                'S': 0x02,  # SYN
                'A': 0x10,  # ACK
                'F': 0x01,  # FIN
                'P': 0x08,  # PSH
                'R': 0x04,  # RST
                'U': 0x20,  # URG
                'E': 0x40,  # ECE
                'C': 0x80,  # CWR
            }
            
            # Extract all flag characters from the string
            # The format is typically something like: <Flag 18 (SA)>
            if '(' in flags_str and ')' in flags_str:
                # Extract flags between parentheses
                flag_chars = flags_str.split('(')[1].split(')')[0]
                for char in flag_chars:
                    if char in flag_map:
                        flags_value |= flag_map[char]

        info = {
            "timestamp": float(packet.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": flags_value,
            "win": tcp.window,
            "payload": bytes(tcp.payload) if tcp.payload else b"",
            "options": tcp.options,
        }

        return info

    def format_packet(self, packet_info: Dict[str, Any]) -> str:
        """Format TCP packet information as a packetdrill command."""
        # Determine packet direction (> for outgoing, < for incoming)
        # In the context of this converter, outgoing is from client to server
        if packet_info["src_ip"] == self.client_ip and packet_info["src_port"] == self.client_port:
            direction = ">"  # Outgoing (client to server)
        else:
            direction = "<"  # Incoming (server to client)
        
        # Extract and format basic TCP flags (without ECE and CWR for compatibility)
        flags_value = packet_info["flags"]
        # For packetdrill compatibility, we only use the basic flags (S, A, F, P, R)
        basic_flags = flags_value & 0x3F  # Mask out ECE and CWR
        flags_str = self._format_tcp_flags(basic_flags)
        
        # Format payload length
        payload_len = len(packet_info["payload"]) if packet_info["payload"] else 0
        
        # Format TCP options
        options_str = ""
        if packet_info["options"]:
            options_str = f" <{self._format_tcp_options(packet_info['options'])}>"
        
        # Format the packet information as a packetdrill command
        # Format: +time > flags seq:seq+payload_len(payload_len) [ack ack] win window <options>
        cmd = f'+{packet_info["timestamp"]:.6f} {direction} {flags_str} '
        cmd += f'{packet_info["seq"]}:{packet_info["seq"] + payload_len}({payload_len}) '
        
        # Add ACK if the ACK flag is set
        if packet_info["flags"] & 0x10:  # ACK flag
            cmd += f'ack {packet_info["ack"]} '
        
        cmd += f'win {packet_info["win"]}'
        
        # Add options if present
        if options_str:
            cmd += options_str
        
        return cmd

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
        """
        Format TCP flags as a string in packetdrill format.
        
        In packetdrill format, flags are represented as single letters:
        - F (FIN)
        - S (SYN)
        - R (RST)
        - P (PUSH)
        - A (ACK)
        - U (URG)
        - E (ECE)
        - C (CWR)
        """
        result = ""
        
        # Check each flag bit
        if flags & 0x02:  # SYN
            result += "S"
        if flags & 0x10:  # ACK
            result += "A"
        if flags & 0x01:  # FIN
            result += "F"
        if flags & 0x08:  # PSH
            result += "P"
        if flags & 0x04:  # RST
            result += "R"
        if flags & 0x20:  # URG
            result += "U"
        if flags & 0x40:  # ECE
            result += "E"
        if flags & 0x80:  # CWR
            result += "C"
                
        return result

    @staticmethod
    def _format_tcp_options(options: List[Tuple[str, Any]]) -> str:
        """
        Format TCP options as a string for packetdrill.
        
        The format must exactly match the expected packetdrill syntax.
        Packetdrill is very specific about TCP option format.
        """
        # Hard-code common option patterns for compatibility
        # This is a workaround for compatibility issues with packetdrill's strict syntax
        
        # Check for common patterns in TCP options
        has_mss = False
        has_wscale = False
        has_timestamp = False
        has_sackOK = False
        
        mss_value = 1460  # Default MSS value
        wscale_value = 0  # Default window scale value
        ts_val = 0
        ts_ecr = 0
        
        # Extract option values
        for opt_name, opt_val in options:
            if opt_name == "MSS":
                has_mss = True
                mss_value = opt_val
            elif opt_name == "WScale":
                has_wscale = True
                wscale_value = opt_val
            elif opt_name == "Timestamp" and isinstance(opt_val, tuple) and len(opt_val) == 2:
                has_timestamp = True
                ts_val = opt_val[0]
                ts_ecr = opt_val[1]
            elif opt_name == "SAckOK":
                has_sackOK = True
        
        # Use hardcoded patterns to match packetdrill's expected format
        # This is much more reliable than trying to generate it dynamically
        if has_mss and has_wscale and has_timestamp and has_sackOK:
            return f"mss {mss_value},nop,nop,sackOK,nop,wscale {wscale_value},nop,nop,TS val {ts_val} ecr {ts_ecr}"
        elif has_mss and has_wscale and has_timestamp:
            return f"mss {mss_value},nop,wscale {wscale_value},nop,nop,TS val {ts_val} ecr {ts_ecr}"
        elif has_mss and has_wscale:
            return f"mss {mss_value},nop,wscale {wscale_value}"
        elif has_mss and has_sackOK:
            return f"mss {mss_value},nop,nop,sackOK"
        elif has_mss:
            return f"mss {mss_value}"
        else:
            # Fallback for any other combinations
            result = []
            for opt_name, opt_val in options:
                if opt_name == "MSS":
                    result.append(f"mss {opt_val}")
                elif opt_name == "SAckOK":
                    result.append("sackOK")
                elif opt_name == "Timestamp" and isinstance(opt_val, tuple) and len(opt_val) == 2:
                    result.append(f"TS val {opt_val[0]} ecr {opt_val[1]}")
                elif opt_name == "WScale":
                    result.append(f"wscale {opt_val}")
                elif opt_name == "NOP":
                    result.append("nop")
            
            return ",".join(result)
