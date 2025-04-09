"""
Replay test script generator for PCAP files.

This module generates packetdrill replay test scripts for complete connection
cycles detected in PCAP files.
"""

import os
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

import jinja2
from scapy.all import Packet, rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.contrib.sctp import SCTP

from pcap2packetdrill.flow_analyzer import FlowAnalyzer
from pcap2packetdrill.protocols import SUPPORTED_PROTOCOLS


class ReplayTestGenerator:
    """Generate packetdrill replay test scripts for complete connection cycles."""

    def __init__(
        self,
        pcap_file: str,
        output_dir: str = ".",
        template_dir: Optional[str] = None,
        relative_time: bool = True,
        debug: bool = False,
    ):
        """
        Initialize the replay test generator.
        
        Args:
            pcap_file: Path to the input PCAP file
            output_dir: Directory to write output test scripts
            template_dir: Directory containing custom templates (optional)
            relative_time: Whether to use relative timestamps
            debug: Enable debug logging
        """
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.template_dir = template_dir
        self.relative_time = relative_time
        
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.replay_generator")
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
        
        # Initialize the flow analyzer
        self.flow_analyzer = FlowAnalyzer(debug=debug)
        
        # Protocol handlers
        self.protocol_handlers = SUPPORTED_PROTOCOLS
    
    def generate_replay_tests(self) -> Dict[str, str]:
        """
        Generate replay test scripts for all complete connection cycles in the PCAP.
        
        Returns:
            Dictionary mapping test names to test script content
        """
        self.logger.info(f"Reading PCAP file: {self.pcap_file}")
        packets = rdpcap(self.pcap_file)
        
        if not packets:
            raise ValueError("No packets found in the PCAP file")
        
        # Identify all flows
        flows = self.flow_analyzer.identify_flows(packets)
        
        # Find complete TCP connection cycles
        tcp_cycles = self.flow_analyzer.identify_tcp_connection_cycles(flows)
        
        # Find complete SCTP association cycles
        sctp_cycles = self.flow_analyzer.identify_sctp_association_cycles(flows)
        
        # Generate test scripts
        test_scripts = {}
        
        # Process TCP connection cycles
        for flow_id, cycles in tcp_cycles.items():
            protocol, src_ip, dst_ip, src_port, dst_port = self.flow_analyzer.parse_flow_id(flow_id)
            
            for i, cycle in enumerate(cycles):
                # Generate a descriptive test name
                test_name = f"tcp_{src_ip.replace('.', '_')}_{src_port}_to_{dst_ip.replace('.', '_')}_{dst_port}_cycle_{i+1}"
                
                # Convert the cycle packets to a test script
                script = self._generate_tcp_replay_script(cycle, src_ip, src_port, dst_ip, dst_port)
                
                test_scripts[test_name] = script
        
        # Process SCTP association cycles
        for flow_id, cycles in sctp_cycles.items():
            protocol, src_ip, dst_ip, src_port, dst_port = self.flow_analyzer.parse_flow_id(flow_id)
            
            for i, cycle in enumerate(cycles):
                # Generate a descriptive test name
                test_name = f"sctp_{src_ip.replace('.', '_')}_{src_port}_to_{dst_ip.replace('.', '_')}_{dst_port}_cycle_{i+1}"
                
                # Convert the cycle packets to a test script
                script = self._generate_sctp_replay_script(cycle, src_ip, src_port, dst_ip, dst_port)
                
                test_scripts[test_name] = script
        
        self.logger.info(f"Generated {len(test_scripts)} replay test scripts")
        
        # Save the test scripts to files
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        for test_name, script in test_scripts.items():
            output_path = os.path.join(self.output_dir, f"{test_name}.pkt")
            with open(output_path, "w") as f:
                f.write(script)
            self.logger.info(f"Wrote test script to: {output_path}")
        
        return test_scripts
    
    def _generate_tcp_replay_script(
        self, 
        cycle: List[Packet], 
        client_ip: str, 
        client_port: int, 
        server_ip: str, 
        server_port: int
    ) -> str:
        """
        Generate a TCP replay test script for a complete connection cycle.
        
        Args:
            cycle: List of packets in the connection cycle
            client_ip: Client IP address
            client_port: Client port
            server_ip: Server IP address
            server_port: Server port
            
        Returns:
            Packetdrill test script content
        """
        # Extract packet information
        packets_info = []
        
        # Get TCP protocol handler
        protocol_handler = self.protocol_handlers["tcp"]
        
        # Process each packet
        for packet in cycle:
            if IP in packet and TCP in packet:
                packet_info = protocol_handler.extract_packet_info(packet)
                if packet_info:
                    packets_info.append(packet_info)
        
        # Adjust timestamps if needed
        if self.relative_time and packets_info:
            initial_timestamp = packets_info[0]["timestamp"]
            for packet_info in packets_info:
                packet_info["timestamp"] -= initial_timestamp
        
        # Format packets into Packetdrill commands
        formatted_packets = [
            protocol_handler.format_packet(packet_info)
            for packet_info in packets_info
        ]
        
        # Generate preconditions and postconditions
        preconditions = [
            "Create a TCP socket",
            "Set appropriate socket options",
            "Bind to client address",
            "Connect to server"
        ]
        
        postconditions = [
            "Ensure connection was established successfully",
            "Verify data was transferred correctly",
            "Ensure connection was closed gracefully"
        ]
        
        # Load template and render output
        template = self._load_template("tcp")
        script = template.render(
            packets=formatted_packets,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            protocol="tcp",
            preconditions=preconditions,
            postconditions=postconditions
        )
        
        return script
    
    def _generate_sctp_replay_script(
        self, 
        cycle: List[Packet], 
        client_ip: str, 
        client_port: int, 
        server_ip: str, 
        server_port: int
    ) -> str:
        """
        Generate an SCTP replay test script for a complete association cycle.
        
        Args:
            cycle: List of packets in the association cycle
            client_ip: Client IP address
            client_port: Client port
            server_ip: Server IP address
            server_port: Server port
            
        Returns:
            Packetdrill test script content
        """
        # Extract packet information
        packets_info = []
        
        # Get SCTP protocol handler
        protocol_handler = self.protocol_handlers["sctp"]
        
        # Process each packet
        for packet in cycle:
            if IP in packet and SCTP in packet:
                packet_info = protocol_handler.extract_packet_info(packet)
                if packet_info:
                    packets_info.append(packet_info)
        
        # Adjust timestamps if needed
        if self.relative_time and packets_info:
            initial_timestamp = packets_info[0]["timestamp"]
            for packet_info in packets_info:
                packet_info["timestamp"] -= initial_timestamp
        
        # Format packets into Packetdrill commands
        formatted_packets = [
            protocol_handler.format_packet(packet_info)
            for packet_info in packets_info
        ]
        
        # Generate preconditions and postconditions
        preconditions = [
            "Create an SCTP socket",
            "Set appropriate socket options",
            "Bind to client address",
            "Connect to server"
        ]
        
        postconditions = [
            "Ensure association was established successfully",
            "Verify data was transferred correctly",
            "Ensure association was terminated properly"
        ]
        
        # Load template and render output
        template = self._load_template("sctp")
        script = template.render(
            packets=formatted_packets,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            protocol="sctp",
            preconditions=preconditions,
            postconditions=postconditions
        )
        
        return script
    
    def _load_template(self, protocol: str) -> jinja2.Template:
        """
        Load the template for generating the packetdrill script.
        
        Args:
            protocol: Protocol name (tcp, udp, sctp)
            
        Returns:
            Jinja2 template object
        """
        if self.template_dir:
            # Look for a specific template in the custom template directory
            template_path = os.path.join(self.template_dir, f"{protocol}_replay.j2")
            if os.path.exists(template_path):
                template_dir = os.path.dirname(template_path)
                template_name = os.path.basename(template_path)
                env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
                return env.get_template(template_name)
                
            # Look for a generic replay template
            template_path = os.path.join(self.template_dir, "replay.j2")
            if os.path.exists(template_path):
                template_dir = os.path.dirname(template_path)
                template_name = os.path.basename(template_path)
                env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
                return env.get_template(template_name)
        
        # Load default template from the package
        module_dir = os.path.dirname(os.path.abspath(__file__))
        templates_dir = os.path.join(module_dir, "templates")
        
        # Look for a specific replay template
        replay_template = f"{protocol}_replay.j2"
        
        # Create a template loader that looks for templates in the package
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(templates_dir),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        
        # Try to load a specific replay template, fall back to the regular template
        try:
            return env.get_template(replay_template)
        except jinja2.exceptions.TemplateNotFound:
            return env.get_template(f"{protocol}.j2")
