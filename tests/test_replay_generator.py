"""
Tests for the replay generator module.

This module contains unit tests for the ReplayTestGenerator class, which is
responsible for generating replay test scripts from complete connection cycles.
"""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock

from pcap2packetdrill.replay_generator import ReplayTestGenerator


class TestReplayTestGenerator(unittest.TestCase):
    """Test cases for the ReplayTestGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for output files
        self.temp_dir = tempfile.mkdtemp()
        
        # Define common test values
        self.client_ip = "192.168.1.1"
        self.server_ip = "192.168.1.2"
        self.client_port = 12345
        self.server_port = 80
        
        # Mock PCAP file path
        self.mock_pcap_file = "mock.pcap"
        
        # Set up patch for rdpcap function
        self.rdpcap_patcher = patch('pcap2packetdrill.replay_generator.rdpcap')
        self.mock_rdpcap = self.rdpcap_patcher.start()
        self.mock_rdpcap.return_value = []  # Default to empty packet list
        
        # Set up patch for FlowAnalyzer
        self.flow_analyzer_patcher = patch('pcap2packetdrill.replay_generator.FlowAnalyzer')
        self.mock_analyzer_class = self.flow_analyzer_patcher.start()
        self.mock_analyzer = Mock()
        self.mock_analyzer_class.return_value = self.mock_analyzer
        
        # Mock the identify_flows method
        self.mock_analyzer.identify_flows.return_value = {}
        
        # Mock the identify_tcp_connection_cycles method
        self.mock_analyzer.identify_tcp_connection_cycles.return_value = {}
        
        # Mock the identify_sctp_association_cycles method
        self.mock_analyzer.identify_sctp_association_cycles.return_value = {}
        
    def tearDown(self):
        """Tear down test fixtures."""
        # Stop all patchers
        self.rdpcap_patcher.stop()
        self.flow_analyzer_patcher.stop()
        
        # Clean up the temporary directory
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)
    
    def test_init(self):
        """Test initialization of the ReplayTestGenerator."""
        # Test initialization with valid parameters
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir,
                relative_time=True,
                debug=False
            )
            
            self.assertEqual(generator.pcap_file, self.mock_pcap_file)
            self.assertEqual(generator.output_dir, self.temp_dir)
            self.assertEqual(generator.template_dir, None)
            self.assertEqual(generator.relative_time, True)
            
        # Test initialization with non-existent PCAP file
        with patch('os.path.exists', return_value=False):
            with self.assertRaises(FileNotFoundError):
                ReplayTestGenerator(
                    pcap_file="nonexistent.pcap",
                    output_dir=self.temp_dir
                )
                
        # Test initialization with invalid output directory
        with patch('os.path.exists', side_effect=lambda x: x == self.mock_pcap_file):
            with patch('os.path.isdir', return_value=False):
                with patch('os.path.isfile', return_value=True):
                    with self.assertRaises(ValueError):
                        ReplayTestGenerator(
                            pcap_file=self.mock_pcap_file,
                            output_dir="not_a_directory"
                        )
    
    def test_generate_replay_tests_empty_pcap(self):
        """Test generating replay tests with an empty PCAP file."""
        # Configure mocks for empty PCAP
        self.mock_rdpcap.return_value = []
        
        # Initialize the generator
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
            
        # Test generating tests from empty PCAP
        with self.assertRaises(ValueError):
            generator.generate_replay_tests()
    
    def test_generate_replay_tests_no_flows(self):
        """Test generating replay tests when no flows are identified."""
        # Configure mocks for PCAP with packets but no flows
        mock_packets = [Mock()]
        self.mock_rdpcap.return_value = mock_packets
        self.mock_analyzer.identify_flows.return_value = {}
        
        # Initialize the generator
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
            
        # Test generating tests with no flows
        result = generator.generate_replay_tests()
        self.assertEqual(result, {})
        
        # Verify the methods were called
        self.mock_rdpcap.assert_called_once_with(self.mock_pcap_file)
        self.mock_analyzer.identify_flows.assert_called_once_with(mock_packets)
        self.mock_analyzer.identify_tcp_connection_cycles.assert_called_once_with({})
        self.mock_analyzer.identify_sctp_association_cycles.assert_called_once_with({})
    
    def test_generate_replay_tests_with_tcp_cycles(self):
        """Test generating replay tests with TCP connection cycles."""
        # Configure mocks for PCAP with TCP connection cycles
        mock_packets = [Mock()]
        self.mock_rdpcap.return_value = mock_packets
        
        # Set up mock flows
        mock_flows = {"tcp:192.168.1.1:12345-192.168.1.2:80": [Mock()]}
        self.mock_analyzer.identify_flows.return_value = mock_flows
        
        # Set up mock TCP cycles
        mock_tcp_cycles = {
            "tcp:192.168.1.1:12345-192.168.1.2:80": [[Mock(), Mock(), Mock()]]
        }
        self.mock_analyzer.identify_tcp_connection_cycles.return_value = mock_tcp_cycles
        
        # Set up mock parse_flow_id
        self.mock_analyzer.parse_flow_id.return_value = (
            "tcp", "192.168.1.1", "192.168.1.2", 12345, 80
        )
        
        # Initialize the generator with a mock for _generate_tcp_replay_script
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
            
        # Mock the _generate_tcp_replay_script method
        generator._generate_tcp_replay_script = Mock(return_value="TCP Script Content")
        
        # Mock the file writing operations
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            # Test generating tests with TCP cycles
            result = generator.generate_replay_tests()
            self.assertEqual(len(result), 1)
            self.assertIn("tcp_192_168_1_1_12345_to_192_168_1_2_80_cycle_1", result)
            
            # Verify the _generate_tcp_replay_script method was called
            generator._generate_tcp_replay_script.assert_called_once()
            
            # Verify the file was written
            mock_file.assert_called()
    
    def test_generate_replay_tests_with_sctp_cycles(self):
        """Test generating replay tests with SCTP association cycles."""
        # Configure mocks for PCAP with SCTP association cycles
        mock_packets = [Mock()]
        self.mock_rdpcap.return_value = mock_packets
        
        # Set up mock flows
        mock_flows = {"sctp:192.168.1.1:12345-192.168.1.2:8080": [Mock()]}
        self.mock_analyzer.identify_flows.return_value = mock_flows
        
        # Set up mock SCTP cycles
        mock_sctp_cycles = {
            "sctp:192.168.1.1:12345-192.168.1.2:8080": [[Mock(), Mock(), Mock(), Mock()]]
        }
        self.mock_analyzer.identify_sctp_association_cycles.return_value = mock_sctp_cycles
        
        # Set up mock parse_flow_id
        self.mock_analyzer.parse_flow_id.return_value = (
            "sctp", "192.168.1.1", "192.168.1.2", 12345, 8080
        )
        
        # Initialize the generator with a mock for _generate_sctp_replay_script
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
            
        # Mock the _generate_sctp_replay_script method
        generator._generate_sctp_replay_script = Mock(return_value="SCTP Script Content")
        
        # Mock the file writing operations
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            # Test generating tests with SCTP cycles
            result = generator.generate_replay_tests()
            self.assertEqual(len(result), 1)
            self.assertIn("sctp_192_168_1_1_12345_to_192_168_1_2_8080_cycle_1", result)
            
            # Verify the _generate_sctp_replay_script method was called
            generator._generate_sctp_replay_script.assert_called_once()
            
            # Verify the file was written
            mock_file.assert_called()
    
    def test_load_template(self):
        """Test loading templates for script generation."""
        # Initialize the generator
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
        
        # Test with invalid protocol
        with self.assertRaises(ValueError):
            generator._load_template("invalid")
        
        # Test loading from package templates (mocked)
        with patch('os.path.isdir', return_value=True):
            with patch('jinja2.Environment.get_template') as mock_get_template:
                mock_template = Mock()
                mock_get_template.return_value = mock_template
                
                # Test loading TCP template
                result = generator._load_template("tcp")
                self.assertEqual(result, mock_template)
                
                # Verify the correct template was requested
                mock_get_template.assert_called_with("tcp_replay.j2")
    
    @patch('pcap2packetdrill.replay_generator.ReplayTestGenerator._load_template')
    def test_generate_tcp_replay_script(self, mock_load_template):
        """Test generating a TCP replay script."""
        # Mock the template
        mock_template = Mock()
        mock_template.render.return_value = "TCP Script Content"
        mock_load_template.return_value = mock_template
        
        # Initialize the generator
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
        
        # Mock extract_packet_info and format_packet
        protocol_handler = Mock()
        protocol_handler.extract_packet_info.return_value = {"timestamp": 1.0}
        protocol_handler.format_packet.return_value = "Formatted Packet"
        generator.protocol_handlers = {"tcp": protocol_handler}
        
        # Test generating TCP script with valid parameters
        mock_packets = [Mock()]
        # Ensure the mock packets have IP and TCP layers
        for packet in mock_packets:
            packet.__contains__ = Mock(side_effect=lambda x: x in [IP, TCP])
        
        result = generator._generate_tcp_replay_script(
            mock_packets, self.client_ip, self.client_port, self.server_ip, self.server_port
        )
        
        self.assertEqual(result, "TCP Script Content")
        mock_template.render.assert_called_once()
        
        # Test with invalid parameters
        with self.assertRaises(ValueError):
            generator._generate_tcp_replay_script([], self.client_ip, self.client_port, self.server_ip, self.server_port)
        
        with self.assertRaises(ValueError):
            generator._generate_tcp_replay_script(
                mock_packets, "invalid-ip", self.client_port, self.server_ip, self.server_port
            )
        
        with self.assertRaises(ValueError):
            generator._generate_tcp_replay_script(
                mock_packets, self.client_ip, 70000, self.server_ip, self.server_port
            )
    
    @patch('pcap2packetdrill.replay_generator.ReplayTestGenerator._load_template')
    def test_generate_sctp_replay_script(self, mock_load_template):
        """Test generating an SCTP replay script."""
        # Mock the template
        mock_template = Mock()
        mock_template.render.return_value = "SCTP Script Content"
        mock_load_template.return_value = mock_template
        
        # Initialize the generator
        with patch('os.path.exists', return_value=True):
            generator = ReplayTestGenerator(
                pcap_file=self.mock_pcap_file,
                output_dir=self.temp_dir
            )
        
        # Mock extract_packet_info and format_packet
        protocol_handler = Mock()
        protocol_handler.extract_packet_info.return_value = {"timestamp": 1.0}
        protocol_handler.format_packet.return_value = "Formatted Packet"
        generator.protocol_handlers = {"sctp": protocol_handler}
        
        # Test generating SCTP script with valid parameters
        mock_packets = [Mock()]
        # Ensure the mock packets have IP and SCTP layers
        for packet in mock_packets:
            packet.__contains__ = Mock(side_effect=lambda x: x in [IP, SCTP])
        
        result = generator._generate_sctp_replay_script(
            mock_packets, self.client_ip, self.client_port, self.server_ip, self.server_port
        )
        
        self.assertEqual(result, "SCTP Script Content")
        mock_template.render.assert_called_once()
        
        # Test with invalid parameters
        with self.assertRaises(ValueError):
            generator._generate_sctp_replay_script([], self.client_ip, self.client_port, self.server_ip, self.server_port)
        
        with self.assertRaises(ValueError):
            generator._generate_sctp_replay_script(
                mock_packets, "invalid-ip", self.client_port, self.server_ip, self.server_port
            )
        
        with self.assertRaises(ValueError):
            generator._generate_sctp_replay_script(
                mock_packets, self.client_ip, 70000, self.server_ip, self.server_port
            )


if __name__ == "__main__":
    unittest.main()
