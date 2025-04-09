"""
Flow analysis for PCAP files.

This module provides functionality to identify and extract complete communication 
cycles from PCAP files for various protocols.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

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


class FlowAnalyzer:
    """Analyzes network flows in PCAP files to identify complete communication cycles."""

    def __init__(self, debug: bool = False):
        """
        Initialize the flow analyzer.
        
        Args:
            debug: Enable debug logging
        """
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.flow_analyzer")
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
        
    def get_flow_id(self, protocol: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """
        Generate a consistent flow ID regardless of packet direction.
        
        Args:
            protocol: Protocol name (tcp, udp, sctp)
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Canonical flow ID string
        """
        # Sort the endpoints to ensure consistent flow ID regardless of direction
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    def parse_flow_id(self, flow_id: str) -> Tuple[str, str, str, int, int]:
        """
        Parse a flow ID into its components.
        
        Args:
            flow_id: Flow ID string
            
        Returns:
            Tuple of (protocol, src_ip, dst_ip, src_port, dst_port)
        """
        protocol, endpoints = flow_id.split(":", 1)
        src_endpoint, dst_endpoint = endpoints.split("-")
        src_ip, src_port = src_endpoint.rsplit(":", 1)
        dst_ip, dst_port = dst_endpoint.rsplit(":", 1)
        return protocol, src_ip, dst_ip, int(src_port), int(dst_port)
    
    def identify_flows(self, packets: List[Packet]) -> Dict[str, List[Packet]]:
        """
        Identify all flows in a packet capture.
        
        Args:
            packets: List of packets
            
        Returns:
            Dictionary mapping flow IDs to lists of packets
        """
        flows = defaultdict(list)
        
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    protocol = "tcp"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "udp"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif SCTP in packet:
                    protocol = "sctp"
                    src_port = packet[SCTP].sport
                    dst_port = packet[SCTP].dport
                else:
                    # Skip unsupported protocols
                    continue
                
                flow_id = self.get_flow_id(protocol, src_ip, dst_ip, src_port, dst_port)
                flows[flow_id].append(packet)
        
        self.logger.info(f"Identified {len(flows)} unique flows")
        return flows
    
    def identify_tcp_connection_cycles(self, flows: Dict[str, List[Packet]]) -> Dict[str, List[List[Packet]]]:
        """
        Identify complete TCP connection cycles in the flows.
        
        Args:
            flows: Dictionary mapping flow IDs to lists of packets
            
        Returns:
            Dictionary mapping flow IDs to lists of packet cycles
        """
        connection_cycles = {}
        
        for flow_id, packets in flows.items():
            protocol = flow_id.split(':', 1)[0]
            
            if protocol != 'tcp':
                continue
                
            # Order packets by time
            ordered_packets = sorted(packets, key=lambda p: float(p.time))
            
            # Find connection establishment and termination
            cycles = self._extract_tcp_connection_cycles(ordered_packets)
            
            if cycles:
                connection_cycles[flow_id] = cycles
        
        self.logger.info(f"Identified {len(connection_cycles)} flows with complete TCP connection cycles")
        return connection_cycles
    
    def _extract_tcp_connection_cycles(self, packets: List[Packet]) -> List[List[Packet]]:
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
        
        for packet in packets:
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
    
    def identify_sctp_association_cycles(self, flows: Dict[str, List[Packet]]) -> Dict[str, List[List[Packet]]]:
        """
        Identify complete SCTP association cycles in the flows.
        
        Args:
            flows: Dictionary mapping flow IDs to lists of packets
            
        Returns:
            Dictionary mapping flow IDs to lists of packet cycles
        """
        association_cycles = {}
        
        for flow_id, packets in flows.items():
            protocol = flow_id.split(':', 1)[0]
            
            if protocol != 'sctp':
                continue
                
            # Order packets by time
            ordered_packets = sorted(packets, key=lambda p: float(p.time))
            
            # Find association establishment and termination
            cycles = self._extract_sctp_association_cycles(ordered_packets)
            
            if cycles:
                association_cycles[flow_id] = cycles
        
        self.logger.info(f"Identified {len(association_cycles)} flows with complete SCTP association cycles")
        return association_cycles
    
    def _extract_sctp_association_cycles(self, packets: List[Packet]) -> List[List[Packet]]:
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
        
        for packet in packets:
            if not (IP in packet and SCTP in packet):
                continue
                
            ip = packet[IP]
            sctp = packet[SCTP]
            
            # Check SCTP chunks
            if not hasattr(sctp, 'chunks') or not sctp.chunks:
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
