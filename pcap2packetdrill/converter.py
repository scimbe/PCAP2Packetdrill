"""
PCAP to Packetdrill converter module.

This module handles the conversion of PCAP files into Packetdrill test scripts.
"""

import os
import logging
from typing import Dict, List, Optional, Any, Union, Tuple, Set
from collections import defaultdict

import jinja2
from scapy.all import rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP

# Try to import SCTP, but provide a fallback if not available
try:
    from scapy.contrib.sctp import SCTP
except ImportError:
    # Create a dummy SCTP class for type checking
    class SCTP:
        """Dummy SCTP class for when scapy.contrib.sctp is not available."""
        pass

from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS, ProtocolHandler


class PcapConverter:
    """Converter for PCAP files to Packetdrill test scripts."""

    def __init__(
        self,
        pcap_file: str,
        protocol: Optional[str] = None,
        client_ip: Optional[str] = None,
        server_ip: Optional[str] = None,
        client_port: Optional[int] = None,
        server_port: Optional[int] = None,
        relative_time: bool = True,
        template_file: Optional[str] = None,
        debug: bool = False,
    ):
        """
        Initialize the PCAP converter.

        Args:
            pcap_file: Path to the PCAP file
            protocol: Protocol to filter (tcp, udp, sctp) or None for auto-detection
            client_ip: Client IP address to filter or None for auto-detection
            server_ip: Server IP address to filter or None for auto-detection
            client_port: Client port to filter or None for auto-detection
            server_port: Server port to filter or None for auto-detection
            relative_time: Whether to use relative timestamps
            template_file: Custom Jinja2 template file path or None for default
            debug: Enable debug logging
        """
        self.pcap_file = pcap_file
        self.protocol_name = protocol
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.relative_time = relative_time
        self.template_file = template_file
        
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill")
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
        
        # Protocol handler will be set later
        self.protocol_handler = None
        
        # Storage for flow analysis
        self.detected_protocols = set()
        self.flows = defaultdict(list)
        
    def _analyze_pcap(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyze the PCAP file to identify protocols, flows, and communication patterns.
        
        Args:
            packets: List of packets from the PCAP file
            
        Returns:
            Dictionary with analysis results
        """
        self.logger.info("Analyzing PCAP file structure and communication patterns")
        
        analysis = {
            "protocols": set(),
            "flows": defaultdict(list),
            "ip_addresses": set(),
            "ports": defaultdict(set),
            "flow_statistics": defaultdict(lambda: {
                "packet_count": 0,
                "byte_count": 0,
                "start_time": float('inf'),
                "end_time": 0,
            }),
        }
        
        # First pass: Identify all protocols and flows
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                analysis["ip_addresses"].add(src_ip)
                analysis["ip_addresses"].add(dst_ip)
                
                if TCP in packet:
                    analysis["protocols"].add("tcp")
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    analysis["ports"]["tcp"].add(src_port)
                    analysis["ports"]["tcp"].add(dst_port)
                    
                    # Define flow by 5-tuple: protocol, src_ip, dst_ip, src_port, dst_port
                    # Use canonical representation to ensure same flow has same ID regardless of direction
                    flow_id = self._get_flow_id("tcp", src_ip, dst_ip, src_port, dst_port)
                    analysis["flows"][flow_id].append(packet)
                    
                    # Update flow statistics
                    flow_stats = analysis["flow_statistics"][flow_id]
                    flow_stats["packet_count"] += 1
                    flow_stats["byte_count"] += len(packet)
                    flow_stats["start_time"] = min(flow_stats["start_time"], float(packet.time))
                    flow_stats["end_time"] = max(flow_stats["end_time"], float(packet.time))
                    
                elif UDP in packet:
                    analysis["protocols"].add("udp")
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    analysis["ports"]["udp"].add(src_port)
                    analysis["ports"]["udp"].add(dst_port)
                    
                    flow_id = self._get_flow_id("udp", src_ip, dst_ip, src_port, dst_port)
                    analysis["flows"][flow_id].append(packet)
                    
                    flow_stats = analysis["flow_statistics"][flow_id]
                    flow_stats["packet_count"] += 1
                    flow_stats["byte_count"] += len(packet)
                    flow_stats["start_time"] = min(flow_stats["start_time"], float(packet.time))
                    flow_stats["end_time"] = max(flow_stats["end_time"], float(packet.time))
                    
                elif SCTP in packet:
                    analysis["protocols"].add("sctp")
                    src_port = packet[SCTP].sport
                    dst_port = packet[SCTP].dport
                    analysis["ports"]["sctp"].add(src_port)
                    analysis["ports"]["sctp"].add(dst_port)
                    
                    flow_id = self._get_flow_id("sctp", src_ip, dst_ip, src_port, dst_port)
                    analysis["flows"][flow_id].append(packet)
                    
                    flow_stats = analysis["flow_statistics"][flow_id]
                    flow_stats["packet_count"] += 1
                    flow_stats["byte_count"] += len(packet)
                    flow_stats["start_time"] = min(flow_stats["start_time"], float(packet.time))
                    flow_stats["end_time"] = max(flow_stats["end_time"], float(packet.time))
        
        # Second pass: Identify significant flows and connection patterns
        significant_flows = {}
        for flow_id, packets in analysis["flows"].items():
            protocol, src_ip, dst_ip, src_port, dst_port = self._parse_flow_id(flow_id)
            
            # Check if this is a significant flow (e.g., complete connection)
            if protocol == "tcp":
                is_complete = self._analyze_tcp_flow(packets)
                if is_complete:
                    significant_flows[flow_id] = {
                        "protocol": protocol,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "packet_count": analysis["flow_statistics"][flow_id]["packet_count"],
                        "byte_count": analysis["flow_statistics"][flow_id]["byte_count"],
                        "duration": analysis["flow_statistics"][flow_id]["end_time"] - analysis["flow_statistics"][flow_id]["start_time"],
                        "complete": True
                    }
            elif protocol == "udp":
                # For UDP, check if there's bidirectional communication
                has_response = self._analyze_udp_flow(packets)
                significant_flows[flow_id] = {
                    "protocol": protocol,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_count": analysis["flow_statistics"][flow_id]["packet_count"],
                    "byte_count": analysis["flow_statistics"][flow_id]["byte_count"],
                    "duration": analysis["flow_statistics"][flow_id]["end_time"] - analysis["flow_statistics"][flow_id]["start_time"],
                    "bidirectional": has_response
                }
            elif protocol == "sctp":
                # For SCTP, check for association setup
                has_association = self._analyze_sctp_flow(packets)
                if has_association:
                    significant_flows[flow_id] = {
                        "protocol": protocol,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "packet_count": analysis["flow_statistics"][flow_id]["packet_count"],
                        "byte_count": analysis["flow_statistics"][flow_id]["byte_count"],
                        "duration": analysis["flow_statistics"][flow_id]["end_time"] - analysis["flow_statistics"][flow_id]["start_time"],
                        "has_association": True
                    }
        
        analysis["significant_flows"] = significant_flows
        
        # Log analysis summary
        self.logger.info(f"Detected protocols: {analysis['protocols']}")
        self.logger.info(f"Number of flows: {len(analysis['flows'])}")
        self.logger.info(f"Number of significant flows: {len(analysis['significant_flows'])}")
        
        return analysis
        
    def _get_flow_id(self, protocol: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """
        Get a canonical flow ID that's consistent regardless of direction.
        
        Args:
            protocol: Protocol name
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            A canonical flow ID string
        """
        # Sort the endpoints to ensure consistent flow ID
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    def _parse_flow_id(self, flow_id: str) -> Tuple[str, str, str, int, int]:
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
    
    def _analyze_tcp_flow(self, packets: List[Packet]) -> bool:
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
            if TCP in packet:
                flags = packet[TCP].flags
                
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
    
    def _analyze_udp_flow(self, packets: List[Packet]) -> bool:
        """
        Analyze a UDP flow to determine if it has bidirectional communication.
        
        Args:
            packets: List of packets in the flow
            
        Returns:
            True if the flow contains bidirectional UDP communication
        """
        # Get the first packet's endpoints
        if not packets or not (IP in packets[0] and UDP in packets[0]):
            return False
            
        first_src_ip = packets[0][IP].src
        first_dst_ip = packets[0][IP].dst
        
        # Check if there are packets in the reverse direction
        for packet in packets[1:]:
            if IP in packet and UDP in packet:
                if packet[IP].src == first_dst_ip and packet[IP].dst == first_src_ip:
                    return True
        
        return False
    
    def _analyze_sctp_flow(self, packets: List[Packet]) -> bool:
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
    
    def _auto_detect_protocol(self, packets: List[Packet]) -> str:
        """
        Auto-detect the protocol from the packets.
        
        Args:
            packets: List of packets from the PCAP file
            
        Returns:
            Detected protocol name
        
        Raises:
            ValueError: If no supported protocol is detected
        """
        # Count protocol occurrences
        protocol_counts = {"tcp": 0, "udp": 0, "sctp": 0}
        
        for packet in packets:
            if IP in packet:
                if TCP in packet:
                    protocol_counts["tcp"] += 1
                elif UDP in packet:
                    protocol_counts["udp"] += 1
                elif SCTP in packet:
                    protocol_counts["sctp"] += 1
        
        # Determine the most frequent protocol
        max_count = 0
        detected_protocol = None
        
        for protocol, count in protocol_counts.items():
            if count > max_count:
                max_count = count
                detected_protocol = protocol
        
        if detected_protocol is None:
            raise ValueError("No supported protocol detected in the PCAP file")
        
        self.logger.info(f"Auto-detected protocol: {detected_protocol}")
        return detected_protocol
    
    def _filter_packets(self, packets: List[Packet]) -> List[Dict[str, Any]]:
        """
        Filter and extract information from packets.
        
        Args:
            packets: List of packets from the PCAP file
            
        Returns:
            List of packet information dictionaries
        """
        packets_info = []
        
        for packet in packets:
            if not IP in packet:
                continue
                
            packet_info = self.protocol_handler.extract_packet_info(packet)
            if packet_info is None:
                continue
                
            # Filter by endpoints if specified
            if self.client_ip and self.server_ip:
                src_ip, dst_ip = packet_info["src_ip"], packet_info["dst_ip"]
                
                # Check if packet is between our endpoints
                if not ((src_ip == self.client_ip and dst_ip == self.server_ip) or 
                        (src_ip == self.server_ip and dst_ip == self.client_ip)):
                    continue
                    
                # Check ports if specified
                if self.client_port and self.server_port:
                    src_port, dst_port = packet_info["src_port"], packet_info["dst_port"]
                    
                    # Check if packet has the right ports
                    if not ((src_ip == self.client_ip and src_port == self.client_port and
                            dst_ip == self.server_ip and dst_port == self.server_port) or
                            (src_ip == self.server_ip and src_port == self.server_port and
                            dst_ip == self.client_ip and dst_port == self.client_port)):
                        continue
            
            packets_info.append(packet_info)
        
        return packets_info
        
    def _adjust_timestamps(self, packets_info: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Adjust timestamps to be relative if required.
        
        Args:
            packets_info: List of packet information dictionaries
            
        Returns:
            List of packet information dictionaries with adjusted timestamps
        """
        if not packets_info:
            return packets_info
            
        # Only adjust timestamps if relative_time is True
        if self.relative_time:
            # Create a copy to avoid modifying the original
            adjusted_packets = packets_info.copy()
            
            # Get the timestamp of the first packet
            initial_timestamp = adjusted_packets[0]["timestamp"]
            
            # Adjust all timestamps
            for packet_info in adjusted_packets:
                packet_info["timestamp"] -= initial_timestamp
                
            return adjusted_packets
        else:
            # Return original timestamps
            return packets_info
    
    def _load_template(self) -> jinja2.Template:
        """
        Load the template for generating the Packetdrill script.
        
        Returns:
            Jinja2 template object
        """
        if self.template_file:
            # Load custom template
            template_dir = os.path.dirname(os.path.abspath(self.template_file))
            template_name = os.path.basename(self.template_file)
            env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
            return env.get_template(template_name)
        else:
            # Load default template
            module_dir = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(module_dir, "templates")
            
            # Create a template loader that looks for templates in the package
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(templates_dir),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            
            return env.get_template(f"{self.protocol_name}.j2")
            
    def _generate_test_case(self, protocol: str, flow_info: Dict[str, Any], 
                           packets_info: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a complete test case for a specific protocol flow.
        
        Args:
            protocol: Protocol name
            flow_info: Information about the flow
            packets_info: List of packet information dictionaries
            
        Returns:
            Dictionary with test case information
        """
        test_case = {
            "protocol": protocol,
            "client_ip": flow_info["src_ip"],
            "client_port": flow_info["src_port"],
            "server_ip": flow_info["dst_ip"],
            "server_port": flow_info["dst_port"],
            "packets": packets_info,
            "preconditions": [],
            "postconditions": []
        }
        
        # Generate preconditions based on protocol
        if protocol == "tcp":
            test_case["preconditions"] = [
                "Create a TCP socket",
                "Set appropriate socket options",
                "Bind to client address",
                "Connect to server"
            ]
            
            # Generate postconditions based on connection status
            if flow_info.get("complete", False):
                test_case["postconditions"] = [
                    "Ensure connection was established successfully",
                    "Close socket gracefully"
                ]
            else:
                test_case["postconditions"] = [
                    "Handle connection errors appropriately",
                    "Close socket"
                ]
                
        elif protocol == "udp":
            test_case["preconditions"] = [
                "Create a UDP socket",
                "Set appropriate socket options",
                "Bind to client address"
            ]
            
            # Generate postconditions based on whether it's bidirectional
            if flow_info.get("bidirectional", False):
                test_case["postconditions"] = [
                    "Verify expected responses were received",
                    "Close socket"
                ]
            else:
                test_case["postconditions"] = [
                    "Handle lack of response appropriately",
                    "Close socket"
                ]
                
        elif protocol == "sctp":
            test_case["preconditions"] = [
                "Create an SCTP socket",
                "Set appropriate socket options",
                "Bind to client address",
                "Connect to server"
            ]
            
            # Generate postconditions based on association status
            if flow_info.get("has_association", False):
                test_case["postconditions"] = [
                    "Ensure association was established successfully",
                    "Close association gracefully"
                ]
            else:
                test_case["postconditions"] = [
                    "Handle association errors appropriately",
                    "Close socket"
                ]
        
        return test_case
    
    def convert(self) -> Dict[str, str]:
        """
        Convert the PCAP file to Packetdrill test scripts for all detected protocols.
        
        Returns:
            Dictionary mapping protocol names to generated Packetdrill scripts
        
        Raises:
            ValueError: If the conversion fails
        """
        self.logger.info(f"Reading PCAP file: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        
        if not packets:
            raise ValueError("No packets found in the PCAP file")
        
        # Analyze PCAP structure
        analysis = self._analyze_pcap(packets)
        
        # Generate test scripts for each protocol with significant flows
        generated_scripts = {}
        
        for protocol in analysis["protocols"]:
            # Get significant flows for this protocol
            protocol_flows = {
                flow_id: info for flow_id, info in analysis["significant_flows"].items()
                if info["protocol"] == protocol
            }
            
            if not protocol_flows:
                self.logger.info(f"No significant {protocol.upper()} flows found for test generation")
                continue
                
            # Take the most significant flow (most packets or most complete)
            best_flow_id = None
            best_flow_score = -1
            
            for flow_id, flow_info in protocol_flows.items():
                # Score flows based on completeness and packet count
                score = flow_info["packet_count"] * 10
                
                if protocol == "tcp" and flow_info.get("complete", False):
                    score += 100
                if protocol == "udp" and flow_info.get("bidirectional", False):
                    score += 100
                if protocol == "sctp" and flow_info.get("has_association", False):
                    score += 100
                    
                if score > best_flow_score:
                    best_flow_score = score
                    best_flow_id = flow_id
            
            if best_flow_id is None:
                continue
                
            # Set up for conversion of this flow
            self.protocol_name = protocol
            flow_info = protocol_flows[best_flow_id]
            self.client_ip = flow_info["src_ip"]
            self.client_port = flow_info["src_port"]
            self.server_ip = flow_info["dst_ip"]
            self.server_port = flow_info["dst_port"]
            
            # Get protocol handler
            self.protocol_handler = SUPPORTED_PROTOCOLS[protocol.lower()]
            
            # Filter and process packets for this flow
            flow_packets = analysis["flows"][best_flow_id]
            packets_info = self._filter_packets(flow_packets)
            
            if not packets_info:
                self.logger.warning(f"No packets extracted for {protocol.upper()} flow")
                continue
                
            # Generate test case with pre/post conditions
            test_case = self._generate_test_case(protocol, flow_info, packets_info)
            
            # Adjust timestamps
            packets_info = self._adjust_timestamps(packets_info)
            
            # Format packets into Packetdrill commands
            formatted_packets = [
                self.protocol_handler.format_packet(packet_info)
                for packet_info in packets_info
            ]
            
            # Load template and render output
            template = self._load_template()
            script = template.render(
                packets=formatted_packets,
                client_ip=self.client_ip,
                client_port=self.client_port,
                server_ip=self.server_ip,
                server_port=self.server_port,
                protocol=self.protocol_name,
                preconditions=test_case["preconditions"],
                postconditions=test_case["postconditions"]
            )
            
            # Add generated script to results
            generated_scripts[protocol] = script
            self.logger.info(f"Generated {protocol.upper()} test script with {len(formatted_packets)} packets")
        
        if not generated_scripts:
            raise ValueError("No test scripts could be generated from the PCAP file")
            
        return generated_scripts
    
    def convert_single(self) -> str:
        """
        Convert the PCAP file to a single Packetdrill script for the specified or auto-detected protocol.
        
        This is the original conversion method that generates a script for a single protocol.
        
        Returns:
            Generated Packetdrill script as a string
        
        Raises:
            ValueError: If the conversion fails
        """
        self.logger.info(f"Reading PCAP file: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        
        if not packets:
            raise ValueError("No packets found in the PCAP file")
            
        # Auto-detect protocol if not specified
        if not self.protocol_name:
            self.protocol_name = self._auto_detect_protocol(packets)
            
        # Get the protocol handler
        if self.protocol_name.lower() not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {self.protocol_name}")
            
        self.protocol_handler = SUPPORTED_PROTOCOLS[self.protocol_name.lower()]
        
        # Extract and filter packet information
        packets_info = self._filter_packets(packets)
        
        if not packets_info:
            raise ValueError("No matching packets found after filtering")
            
        # Identify endpoints if not specified
        if not (self.client_ip and self.server_ip and self.client_port and self.server_port):
            self.client_ip, self.client_port, self.server_ip, self.server_port = \
                self.protocol_handler.identify_endpoints(packets_info)
            
            self.logger.info(f"Identified client: {self.client_ip}:{self.client_port}")
            self.logger.info(f"Identified server: {self.server_ip}:{self.server_port}")
        
        # Do basic flow analysis to determine pre/post conditions
        flow_info = {
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "dst_ip": self.server_ip,
            "dst_port": self.server_port,
        }
        
        if self.protocol_name == "tcp":
            flow_info["complete"] = self._analyze_tcp_flow(packets)
        elif self.protocol_name == "udp":
            flow_info["bidirectional"] = self._analyze_udp_flow(packets)
        elif self.protocol_name == "sctp":
            flow_info["has_association"] = self._analyze_sctp_flow(packets)
        
        # Generate test case with pre/post conditions
        test_case = self._generate_test_case(self.protocol_name, flow_info, packets_info)
        
        # Adjust timestamps
        packets_info = self._adjust_timestamps(packets_info)
        
        # Format packets into Packetdrill commands
        formatted_packets = [
            self.protocol_handler.format_packet(packet_info)
            for packet_info in packets_info
        ]
        
        # Load template and render output
        template = self._load_template()
        script = template.render(
            packets=formatted_packets,
            client_ip=self.client_ip,
            client_port=self.client_port,
            server_ip=self.server_ip,
            server_port=self.server_port,
            protocol=self.protocol_name,
            preconditions=test_case["preconditions"],
            postconditions=test_case["postconditions"]
        )
        
        return script
