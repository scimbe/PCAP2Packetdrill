"""
SCTP flow analysis module.

This module provides functionality to analyze SCTP flows and extract complete association cycles.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any

from scapy.all import Packet
from scapy.layers.inet import IP

# Try to import SCTP, but provide a fallback if not available
try:
    from scapy.contrib.sctp import SCTP
except ImportError:
    # Create a dummy SCTP class for type checking
    class SCTP:
        """Dummy SCTP class for when scapy.contrib.sctp is not available."""
        pass


class SCTPAnalyzer:
    """Analyzes SCTP flows to identify complete association cycles."""

    def __init__(self, debug: bool = False):
        """
        Initialize the SCTP analyzer.
        
        Args:
            debug: Enable debug logging
        """
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.flow.sctp_analyzer")
        level = logging.DEBUG if debug else logging.INFO
        
        # Configure logging only if not already configured
        if not self.logger.handlers:
            logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
            self.logger.setLevel(level)
    
    def analyze_sctp_flow(self, packets: List[Packet]) -> bool:
        """
        Analyze an SCTP flow to determine if it contains an association setup.
        
        Args:
            packets: List of packets in the flow
            
        Returns:
            True if the flow contains an SCTP association setup
        """
        has_init = False
        has_init_ack = False
        has_cookie_echo = False
        has_cookie_ack = False
        
        for packet in packets:
            if SCTP in packet:
                # Check SCTP chunks
                if hasattr(packet[SCTP], "chunks"):
                    for chunk in packet[SCTP].chunks:
                        chunk_type = getattr(chunk, "type", None)
                        
                        if chunk_type == 1:  # INIT
                            has_init = True
                        elif chunk_type == 2:  # INIT_ACK
                            has_init_ack = True
                        elif chunk_type == 10:  # COOKIE_ECHO
                            has_cookie_echo = True
                        elif chunk_type == 11:  # COOKIE_ACK
                            has_cookie_ack = True
        
        # Consider an association setup if it has at least INIT and INIT_ACK
        return has_init and has_init_ack
    
    def extract_sctp_association_cycles(self, packets: List[Packet]) -> List[List[Packet]]:
        """
        Extract complete SCTP association cycles from an ordered list of packets.
        
        A complete cycle consists of:
        1. Association establishment (INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK)
        2. Data exchange (optional)
        3. Association termination (SHUTDOWN sequence)
        
        Args:
            packets: Time-ordered list of packets in a flow
            
        Returns:
            List of packet lists, each representing a complete association cycle
        """
        cycles = []
        current_cycle = []
        association_state = "CLOSED"
        
        # Track endpoints
        client_ip = None
        server_ip = None
        client_port = None
        server_port = None
        
        # Sort packets by time if not already sorted
        sorted_packets = sorted(packets, key=lambda p: float(p.time))
        
        for packet in sorted_packets:
            if not (IP in packet and SCTP in packet):
                continue
                
            ip = packet[IP]
            sctp = packet[SCTP]
            
            # Check SCTP chunks
            if not hasattr(sctp, 'chunks') or not sctp.chunks:
                # If no chunks, just add the packet to the current cycle if we're in a cycle
                if current_cycle:
                    current_cycle.append(packet)
                continue
                
            # Process each chunk
            for chunk in sctp.chunks:
                chunk_type = getattr(chunk, "type", None)
                
                # Identify association establishment
                if association_state == "CLOSED" and chunk_type == 1:  # INIT
                    # Start of a new association
                    current_cycle = [packet]
                    association_state = "INIT_SENT"
                    client_ip = ip.src
                    client_port = sctp.sport
                    server_ip = ip.dst
                    server_port = sctp.dport
                    break
                    
                # Track the association
                if association_state == "INIT_SENT" and chunk_type == 2:  # INIT-ACK
                    if ip.src == server_ip and ip.dst == client_ip:
                        current_cycle.append(packet)
                        association_state = "COOKIE_ECHO_SENT"
                        break
                
                if association_state == "COOKIE_ECHO_SENT" and chunk_type == 10:  # COOKIE-ECHO
                    if ip.src == client_ip and ip.dst == server_ip:
                        current_cycle.append(packet)
                        association_state = "COOKIE_ECHOED"
                        break
                
                if association_state == "COOKIE_ECHOED" and chunk_type == 11:  # COOKIE-ACK
                    if ip.src == server_ip and ip.dst == client_ip:
                        current_cycle.append(packet)
                        association_state = "ESTABLISHED"
                        break
                
                # Add data packets to the current cycle
                if association_state == "ESTABLISHED":
                    # Add the packet to the current cycle if not already added
                    if packet not in current_cycle:
                        current_cycle.append(packet)
                    
                    # Check for association termination
                    if chunk_type == 7:  # SHUTDOWN
                        association_state = "SHUTDOWN_SENT"
                        break
                    elif chunk_type == 6:  # ABORT
                        association_state = "CLOSED"
                        # Add the current cycle to the list of complete cycles
                        cycles.append(current_cycle)
                        current_cycle = []
                        client_ip = None
                        server_ip = None
                        break
                
                # Handle SHUTDOWN sequence
                elif association_state == "SHUTDOWN_SENT" and chunk_type == 8:  # SHUTDOWN-ACK
                    if packet not in current_cycle:
                        current_cycle.append(packet)
                    association_state = "SHUTDOWN_ACK_SENT"
                    break
                    
                elif association_state == "SHUTDOWN_ACK_SENT" and chunk_type == 14:  # SHUTDOWN-COMPLETE
                    if packet not in current_cycle:
                        current_cycle.append(packet)
                    association_state = "CLOSED"
                    # Add the current cycle to the list of complete cycles
                    cycles.append(current_cycle)
                    current_cycle = []
                    client_ip = None
                    server_ip = None
                    break
        
        # Check if we have a partial association cycle at the end
        if current_cycle and association_state != "CLOSED":
            # If the association was established but not properly closed, we can still use it
            if association_state == "ESTABLISHED" and len(current_cycle) >= 4:  # INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK
                self.logger.warning("Adding incomplete but established SCTP association")
                cycles.append(current_cycle)
        
        return cycles
