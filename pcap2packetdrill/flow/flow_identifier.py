"""
Flow identification module.

This module provides functionality to identify network flows in packet captures.
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


class FlowIdentifier:
    """Identifies network flows in packet captures."""

    def __init__(self, debug: bool = False):
        """
        Initialize the flow identifier.
        
        Args:
            debug: Enable debug logging
        """
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.flow.identifier")
        level = logging.DEBUG if debug else logging.INFO
        
        # Configure logging only if not already configured
        if not self.logger.handlers:
            logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
            self.logger.setLevel(level)
        
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
            # Handle both real packets and Mock objects
            protocol = None
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            
            # Check if packet has IP layer
            if hasattr(packet, '__contains__') and IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Determine protocol and get ports
                if TCP in packet:
                    protocol = "tcp"
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                elif UDP in packet:
                    protocol = "udp"
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                elif SCTP in packet:
                    protocol = "sctp"
                    sctp_layer = packet[SCTP]
                    src_port = sctp_layer.sport
                    dst_port = sctp_layer.dport
            # Handle alternative mock configurations
            elif hasattr(packet, 'haslayer') and callable(packet.haslayer):
                if packet.haslayer(IP):
                    # Try to get IP layer
                    ip_layer = None
                    if hasattr(packet, 'getlayer') and callable(packet.getlayer):
                        ip_layer = packet.getlayer(IP)
                    elif hasattr(packet, '__getitem__'):
                        try:
                            ip_layer = packet[IP]
                        except (TypeError, IndexError):
                            continue
                    
                    if ip_layer:
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        
                        # Determine protocol and get ports
                        if packet.haslayer(TCP):
                            protocol = "tcp"
                            tcp_layer = packet.getlayer(TCP) if hasattr(packet, 'getlayer') else packet[TCP]
                            src_port = tcp_layer.sport
                            dst_port = tcp_layer.dport
                        elif packet.haslayer(UDP):
                            protocol = "udp"
                            udp_layer = packet.getlayer(UDP) if hasattr(packet, 'getlayer') else packet[UDP]
                            src_port = udp_layer.sport
                            dst_port = udp_layer.dport
                        elif packet.haslayer(SCTP):
                            protocol = "sctp"
                            sctp_layer = packet.getlayer(SCTP) if hasattr(packet, 'getlayer') else packet[SCTP]
                            src_port = sctp_layer.sport
                            dst_port = sctp_layer.dport
            
            # If we successfully identified protocol and endpoints, add to flows
            if protocol and src_ip and dst_ip and src_port is not None and dst_port is not None:
                flow_id = self.get_flow_id(protocol, src_ip, dst_ip, src_port, dst_port)
                flows[flow_id].append(packet)
        
        self.logger.info(f"Identified {len(flows)} unique flows")
        return flows
