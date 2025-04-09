"""
PCAP to Packetdrill converter module.

This module handles the conversion of PCAP files into Packetdrill test scripts.
"""

import os
import logging
from typing import Dict, List, Optional, Any, Union, Tuple

import jinja2
from scapy.all import rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.contrib.sctp import SCTP

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
        if not packets_info or not self.relative_time:
            return packets_info
            
        # Get the timestamp of the first packet
        initial_timestamp = packets_info[0]["timestamp"]
        
        # Adjust all timestamps
        for packet_info in packets_info:
            packet_info["timestamp"] -= initial_timestamp
            
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
    
    def convert(self) -> str:
        """
        Convert the PCAP file to a Packetdrill script.
        
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
        )
        
        return script
