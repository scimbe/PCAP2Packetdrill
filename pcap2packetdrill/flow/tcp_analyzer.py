"""
TCP flow analysis module.

This module provides functionality to analyze TCP flows and extract complete connection cycles.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any

from scapy.all import Packet
from scapy.layers.inet import IP, TCP


class TCPAnalyzer:
    """Analyzes TCP flows to identify complete connection cycles."""

    def __init__(self, debug: bool = False):
        """
        Initialize the TCP analyzer.
        
        Args:
            debug: Enable debug logging
        """
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.flow.tcp_analyzer")
        level = logging.DEBUG if debug else logging.INFO
        
        # Configure logging only if not already configured
        if not self.logger.handlers:
            logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
            self.logger.setLevel(level)
    
    def analyze_tcp_flow(self, packets: List[Packet]) -> bool:
        """
        Analyze a TCP flow to determine if it's a complete connection.
        
        Args:
            packets: List of packets in the flow
            
        Returns:
            True if the flow contains a complete TCP connection
        """
        has_syn = False
        has_syn_ack = False
        has_fin = False
        
        for packet in packets:
            # Handle Mock objects safely - check attributes and methods
            # before attempting to use 'in' operator
            if hasattr(packet, '__contains__'):
                # For regular scapy packets and properly configured mocks
                if TCP in packet:
                    tcp = packet[TCP]
                    flags = tcp.flags if hasattr(tcp, 'flags') else 0
                    
                    # Check for SYN flag (connection initiation)
                    if flags & 0x02:  # SYN flag
                        has_syn = True
                    
                    # Check for SYN-ACK (connection establishment)
                    if (flags & 0x12) == 0x12:  # SYN and ACK flags
                        has_syn_ack = True
                    
                    # Check for FIN flag (connection termination)
                    if flags & 0x01:  # FIN flag
                        has_fin = True
            elif hasattr(packet, 'haslayer') and callable(packet.haslayer):
                # Alternative for some mock configurations
                if packet.haslayer(TCP):
                    # Extract TCP layer if possible
                    tcp = None
                    if hasattr(packet, 'getlayer') and callable(packet.getlayer):
                        tcp = packet.getlayer(TCP)
                    elif hasattr(packet, '__getitem__'):
                        try:
                            tcp = packet[TCP]
                        except (TypeError, IndexError):
                            continue
                    
                    if tcp and hasattr(tcp, 'flags'):
                        flags = tcp.flags
                        
                        # Check for SYN flag (connection initiation)
                        if flags & 0x02:  # SYN flag
                            has_syn = True
                        
                        # Check for SYN-ACK (connection establishment)
                        if (flags & 0x12) == 0x12:  # SYN and ACK flags
                            has_syn_ack = True
                        
                        # Check for FIN flag (connection termination)
                        if flags & 0x01:  # FIN flag
                            has_fin = True
        
        # Consider a connection complete if it has at least SYN and SYN-ACK
        return has_syn and has_syn_ack
    
    def extract_tcp_connection_cycles(self, packets: List[Packet]) -> List[List[Packet]]:
        """
        Extract complete TCP connection cycles from an ordered list of packets.
        
        A complete cycle consists of:
        1. Connection establishment (SYN, SYN-ACK, ACK)
        2. Data exchange (optional)
        3. Connection termination (FIN-ACK sequences or RST)
        
        Args:
            packets: Time-ordered list of packets in a flow
            
        Returns:
            List of packet lists, each representing a complete connection cycle
        """
        cycles = []
        current_cycle = []
        connection_state = "CLOSED"
        
        # Track sequence numbers for proper connection tracking
        client_seq = None
        server_seq = None
        client_ip = None
        server_ip = None
        client_port = None
        server_port = None
        
        # Sort packets by time if not already sorted
        sorted_packets = sorted(packets, key=lambda p: float(p.time))
        
        for packet in sorted_packets:
            if not (IP in packet and TCP in packet):
                continue
                
            tcp = packet[TCP]
            ip = packet[IP]
            flags = tcp.flags
            
            # Identify connection establishment
            if connection_state == "CLOSED" and (flags & 0x02):  # SYN flag
                # Start of a new connection
                current_cycle = [packet]
                connection_state = "SYN_SENT"
                client_seq = tcp.seq
                client_ip = ip.src
                client_port = tcp.sport
                server_ip = ip.dst
                server_port = tcp.dport
                continue
                
            # Track the connection
            if connection_state == "SYN_SENT":
                if (flags & 0x12) == 0x12:  # SYN-ACK flags
                    if ip.src == server_ip and ip.dst == client_ip:
                        current_cycle.append(packet)
                        connection_state = "SYN_RECEIVED"
                        server_seq = tcp.seq
                        continue
            
            if connection_state == "SYN_RECEIVED":
                if (flags & 0x10) and not (flags & 0x02):  # ACK flag without SYN
                    if ip.src == client_ip and ip.dst == server_ip:
                        current_cycle.append(packet)
                        connection_state = "ESTABLISHED"
                        continue
            
            # Add data packets to the current cycle
            if connection_state == "ESTABLISHED":
                # Add the packet to the current cycle
                current_cycle.append(packet)
                
                # Check for connection termination
                if (flags & 0x01):  # FIN flag
                    connection_state = "FIN_WAIT" if ip.src == client_ip else "CLOSE_WAIT"
                elif (flags & 0x04):  # RST flag
                    # RST can immediately terminate the connection
                    connection_state = "CLOSED"
                    # Add the current cycle to the list of complete cycles
                    cycles.append(current_cycle)
                    current_cycle = []
                    client_seq = None
                    server_seq = None
                    client_ip = None
                    server_ip = None
                    
            # Handle FIN sequence
            elif connection_state == "FIN_WAIT":
                # Add the packet to current cycle
                current_cycle.append(packet)
                
                # Check for ACK of FIN
                if (flags & 0x10) and not (flags & 0x01) and ip.src == server_ip:
                    connection_state = "FIN_WAIT_2"
                # Or server might send FIN-ACK immediately
                elif (flags & 0x11) == 0x11 and ip.src == server_ip:
                    connection_state = "CLOSING"
                    
            elif connection_state == "FIN_WAIT_2":
                # Add the packet to current cycle
                current_cycle.append(packet)
                
                # Check for server's FIN
                if (flags & 0x01) and ip.src == server_ip:
                    connection_state = "TIME_WAIT"
                    
            elif connection_state == "CLOSE_WAIT":
                # Add the packet to current cycle
                current_cycle.append(packet)
                
                # Check for client's ACK of server's FIN
                if (flags & 0x10) and not (flags & 0x01) and ip.src == client_ip:
                    connection_state = "LAST_ACK"
                    
            elif connection_state == "LAST_ACK":
                # Add the packet to current cycle
                current_cycle.append(packet)
                
                # Check for server's ACK of client's FIN
                if (flags & 0x10) and not (flags & 0x01) and ip.src == server_ip:
                    connection_state = "CLOSED"
                    # Add the current cycle to the list of complete cycles
                    cycles.append(current_cycle)
                    current_cycle = []
                    client_seq = None
                    server_seq = None
                    client_ip = None
                    server_ip = None
                    
            elif connection_state == "CLOSING":
                # Add the packet to current cycle
                current_cycle.append(packet)
                
                # Check for final ACK
                if (flags & 0x10) and not (flags & 0x01):
                    connection_state = "CLOSED"
                    # Add the current cycle to the list of complete cycles
                    cycles.append(current_cycle)
                    current_cycle = []
                    client_seq = None
                    server_seq = None
                    client_ip = None
                    server_ip = None
                    
            elif connection_state == "TIME_WAIT":
                # Add the packet to current cycle
                current_cycle.append(packet)
                
                # Check for client's ACK of server's FIN
                if (flags & 0x10) and not (flags & 0x01) and ip.src == client_ip:
                    connection_state = "CLOSED"
                    # Add the current cycle to the list of complete cycles
                    cycles.append(current_cycle)
                    current_cycle = []
                    client_seq = None
                    server_seq = None
                    client_ip = None
                    server_ip = None
        
        # Check if we have a partial connection cycle at the end
        if current_cycle and connection_state != "CLOSED":
            # If the connection was established but not properly closed, we can still use it
            if connection_state == "ESTABLISHED" and len(current_cycle) >= 3:
                self.logger.warning("Adding incomplete but established TCP connection")
                cycles.append(current_cycle)
        
        return cycles
