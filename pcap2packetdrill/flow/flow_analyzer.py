"""
Flow analyzer module.

This module integrates flow identification and protocol-specific analyzers to extract
complete connection cycles from packet captures.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from scapy.all import Packet

from pcap2packetdrill.flow.flow_identifier import FlowIdentifier
from pcap2packetdrill.flow.tcp_analyzer import TCPAnalyzer
from pcap2packetdrill.flow.sctp_analyzer import SCTPAnalyzer


class FlowAnalyzer:
    """
    Analyzes network flows in PCAP files to identify complete communication cycles.
    
    This class integrates the flow identification and protocol-specific analyzers to
    extract complete connection cycles for different protocols.
    """

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
        
        # Initialize sub-components
        self.flow_identifier = FlowIdentifier(debug=debug)
        self.tcp_analyzer = TCPAnalyzer(debug=debug)
        self.sctp_analyzer = SCTPAnalyzer(debug=debug)
    
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
        return self.flow_identifier.get_flow_id(protocol, src_ip, dst_ip, src_port, dst_port)
    
    def parse_flow_id(self, flow_id: str) -> Tuple[str, str, str, int, int]:
        """
        Parse a flow ID into its components.
        
        Args:
            flow_id: Flow ID string
            
        Returns:
            Tuple of (protocol, src_ip, dst_ip, src_port, dst_port)
        """
        return self.flow_identifier.parse_flow_id(flow_id)
    
    def identify_flows(self, packets: List[Packet]) -> Dict[str, List[Packet]]:
        """
        Identify all flows in a packet capture.
        
        Args:
            packets: List of packets
            
        Returns:
            Dictionary mapping flow IDs to lists of packets
        """
        return self.flow_identifier.identify_flows(packets)
    
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
                
            # Find connection establishment and termination
            cycles = self.tcp_analyzer.extract_tcp_connection_cycles(packets)
            
            if cycles:
                connection_cycles[flow_id] = cycles
        
        self.logger.info(f"Identified {len(connection_cycles)} flows with complete TCP connection cycles")
        return connection_cycles
    
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
                
            # Find association establishment and termination
            cycles = self.sctp_analyzer.extract_sctp_association_cycles(packets)
            
            if cycles:
                association_cycles[flow_id] = cycles
        
        self.logger.info(f"Identified {len(association_cycles)} flows with complete SCTP association cycles")
        return association_cycles
