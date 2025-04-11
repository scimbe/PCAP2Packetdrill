"""
Replay test generator manager module.

This module provides a central manager for generating replay test scripts from
packet captures for different protocols.
"""

import os
import logging
from typing import Dict, List, Optional, Set, Tuple, Any

from scapy.all import Packet, rdpcap

from pcap2packetdrill.flow import FlowAnalyzer
from pcap2packetdrill.generator.tcp_generator import TCPReplayGenerator


class ReplayManager:
    """
    Manager for generating replay test scripts from PCAP files.
    
    This class coordinates the flow analysis and script generation for TCP
    protocol to create replay test scripts.
    """

    def __init__(
        self,
        pcap_file: str,
        output_dir: str = ".",
        template_dir: Optional[str] = None,
        relative_time: bool = True,
        debug: bool = False,
    ):
        """
        Initialize the replay manager.
        
        Args:
            pcap_file: Path to the input PCAP file
            output_dir: Directory to write output test scripts
            template_dir: Directory containing custom templates (optional)
            relative_time: Whether to use relative timestamps
            debug: Enable debug logging
            
        Raises:
            ValueError: If the pcap_file doesn't exist or output_dir is invalid
            FileNotFoundError: If the pcap_file doesn't exist
        """
        # Verify input file exists
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
            
        # Verify output directory is valid
        if not os.path.isdir(output_dir) and output_dir != ".":
            if os.path.exists(output_dir):
                raise ValueError(f"Output path exists but is not a directory: {output_dir}")
                
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        
        # Determine template directory
        if template_dir and os.path.isdir(template_dir):
            self.template_dir = template_dir
        else:
            # Use default templates from the package
            module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.template_dir = os.path.join(module_dir, "templates")
            
        self.relative_time = relative_time
        
        # Set up logging
        self.logger = logging.getLogger("pcap2packetdrill.generator.manager")
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
        self.logger.setLevel(level)
        
        # Debug flag for sub-components
        self.debug = debug
        
        # Initialize analyzers and generators
        self.flow_analyzer = FlowAnalyzer(debug=debug)
        self.tcp_generator = TCPReplayGenerator(self.template_dir, relative_time, debug)
    
    def generate_replay_tests(self) -> Dict[str, str]:
        """
        Generate replay test scripts for all complete TCP connection cycles in the PCAP.
        
        This method:
        1. Reads the PCAP file
        2. Identifies all protocol flows
        3. Finds complete TCP connection cycles
        4. Generates test scripts for each cycle
        5. Saves the scripts to files
        
        Returns:
            Dictionary mapping test names to test script content
            
        Raises:
            ValueError: If the PCAP file has no packets or cannot be parsed
            IOError: If there are issues reading the PCAP file
            OSError: If there are issues creating output files
        """
        self.logger.info(f"Reading PCAP file: {self.pcap_file}")
        
        try:
            packets = rdpcap(self.pcap_file)
            
            if not packets:
                raise ValueError("No packets found in the PCAP file")
                
        except Exception as e:
            error_msg = f"Error reading PCAP file: {e}"
            self.logger.error(error_msg)
            raise IOError(error_msg) from e
        
        # Identify all flows
        try:
            flows = self.flow_analyzer.identify_flows(packets)
        except Exception as e:
            error_msg = f"Error identifying flows: {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg) from e
        
        # Find complete TCP connection cycles
        try:
            tcp_cycles = self.flow_analyzer.identify_tcp_connection_cycles(flows)
            self.logger.info(f"Found {len(tcp_cycles)} flows with TCP connection cycles")
        except Exception as e:
            self.logger.warning(f"Error identifying TCP cycles: {e}")
            tcp_cycles = {}
        
        # Generate test scripts
        test_scripts = {}
        
        # Process TCP connection cycles
        for flow_id, cycles in tcp_cycles.items():
            try:
                protocol, src_ip, dst_ip, src_port, dst_port = self.flow_analyzer.parse_flow_id(flow_id)
                
                for i, cycle in enumerate(cycles):
                    # Generate a descriptive test name with sanitized IP addresses
                    test_name = f"tcp_{src_ip.replace('.', '_')}_{src_port}_to_{dst_ip.replace('.', '_')}_{dst_port}_cycle_{i+1}"
                    
                    # Convert the cycle packets to a test script
                    script = self.tcp_generator.generate_replay_script(
                        cycle, src_ip, src_port, dst_ip, dst_port
                    )
                    
                    test_scripts[test_name] = script
                    self.logger.debug(f"Generated TCP replay test: {test_name}")
            except Exception as e:
                self.logger.warning(f"Error generating TCP test scripts for flow {flow_id}: {e}")
        
        self.logger.info(f"Generated {len(test_scripts)} replay test scripts")
        
        # Save the test scripts to files
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
                
            for test_name, script in test_scripts.items():
                output_path = os.path.join(self.output_dir, f"{test_name}.pkt")
                with open(output_path, "w") as f:
                    f.write(script)
                self.logger.info(f"Wrote test script to: {output_path}")
                
        except Exception as e:
            error_msg = f"Error saving test scripts: {e}"
            self.logger.error(error_msg)
            raise OSError(error_msg) from e
        
        return test_scripts
