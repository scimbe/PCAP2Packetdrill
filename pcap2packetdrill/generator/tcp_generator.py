"""
TCP replay script generator module.

This module provides functionality to generate TCP replay test scripts from packet captures.
"""

import logging
import ipaddress
from typing import Dict, List, Optional, Any, Tuple

from scapy.all import Packet
from scapy.layers.inet import IP, TCP

import jinja2

from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS


class TCPReplayGenerator:
    """Generates TCP replay test scripts from packet captures."""

    def __init__(self, templates_dir: str, relative_time: bool = True, debug: bool = False):
        """
        Initialize the TCP replay generator.
        
        Args:
            templates_dir: Directory containing templates
            relative_time: Whether to use relative timestamps
            debug: Enable debug logging
        """
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.generator.tcp")
        level = logging.DEBUG if debug else logging.INFO
        
        # Configure logging only if not already configured
        if not self.logger.handlers:
            logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
            self.logger.setLevel(level)
            
        self.templates_dir = templates_dir
        self.relative_time = relative_time
        self.protocol_handler = SUPPORTED_PROTOCOLS["tcp"]
    
    def generate_replay_script(
        self, 
        cycle: List[Packet], 
        client_ip: str, 
        client_port: int, 
        server_ip: str, 
        server_port: int
    ) -> str:
        """
        Generate a TCP replay test script for a complete connection cycle.
        
        Creates a packetdrill script that replays the exact TCP connection behavior
        observed in the PCAP, preserving sequence numbers, timestamps, flags,
        and payload data.
        
        Args:
            cycle: List of packets in the connection cycle
            client_ip: Client IP address
            client_port: Client port
            server_ip: Server IP address
            server_port: Server port
            
        Returns:
            Packetdrill test script content
            
        Raises:
            ValueError: If input parameters are invalid
            KeyError: If packet processing fails
        """
        if not cycle:
            raise ValueError("Empty packet cycle provided")
            
        # Validate IP addresses and ports
        try:
            ipaddress.ip_address(client_ip)
            ipaddress.ip_address(server_ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
            
        if not (0 <= client_port <= 65535 and 0 <= server_port <= 65535):
            raise ValueError(f"Invalid port number: {client_port} or {server_port}")
            
        # Extract packet information
        packets_info = []
        
        # Process each packet
        for packet in cycle:
            if IP in packet and TCP in packet:
                try:
                    packet_info = self.protocol_handler.extract_packet_info(packet)
                    if packet_info:
                        packets_info.append(packet_info)
                except Exception as e:
                    self.logger.warning(f"Error extracting packet info: {e}")
        
        if not packets_info:
            raise ValueError("No valid TCP packets found in the cycle")
        
        # Adjust timestamps if needed
        if self.relative_time and packets_info:
            initial_timestamp = packets_info[0]["timestamp"]
            for packet_info in packets_info:
                packet_info["timestamp"] -= initial_timestamp
        
        # Format packets into Packetdrill commands
        formatted_packets = []
        for packet_info in packets_info:
            try:
                formatted_packet = self.protocol_handler.format_packet(packet_info)
                formatted_packets.append(formatted_packet)
            except Exception as e:
                self.logger.warning(f"Error formatting packet: {e}")
        
        # Analyze the TCP flow to determine connection state
        has_data = any(len(p.get("payload", b"")) > 0 for p in packets_info)
        has_fin = any((p.get("flags", 0) & 0x01) for p in packets_info)
        has_complete_handshake = len(packets_info) >= 3  # At minimum SYN, SYN-ACK, ACK
        
        # Generate preconditions and postconditions based on flow analysis
        preconditions = [
            "Create a TCP socket",
            "Set appropriate socket options",
            "Bind to client address",
            "Connect to server"
        ]
        
        postconditions = ["Ensure connection was established successfully"]
        
        if has_data:
            postconditions.append("Verify data was transferred correctly")
            
        if has_fin:
            postconditions.append("Ensure connection was closed gracefully")
        else:
            postconditions.append("Close socket after test completion")
        
        # Load template and render output
        try:
            template = self._load_template("tcp_replay.j2")
            script = template.render(
                packets=formatted_packets,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                protocol="tcp",
                preconditions=preconditions,
                postconditions=postconditions,
                has_data=has_data,
                has_fin=has_fin,
                has_complete_handshake=has_complete_handshake
            )
            return script
        except Exception as e:
            error_msg = f"Error rendering TCP template: {e}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg) from e
            
    def _load_template(self, template_name: str) -> jinja2.Template:
        """
        Load the template for generating the packetdrill script.
        
        Args:
            template_name: Name of the template file
            
        Returns:
            Jinja2 template object
            
        Raises:
            ValueError: If template cannot be found
        """
        try:
            # Create a template loader that looks for templates in the specified directory
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(self.templates_dir),
                trim_blocks=True,
                lstrip_blocks=True,
                auto_reload=False,  # For production use
                autoescape=False,   # No HTML escaping needed
            )
            
            return env.get_template(template_name)
        except jinja2.exceptions.TemplateNotFound:
            error_msg = f"Template not found: {template_name}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
