"""Tests for the PCAP converter."""

import os
import unittest
from unittest.mock import Mock, patch, MagicMock

from pcap2packetdrill.converter import PcapConverter


class TestPcapConverter(unittest.TestCase):
    """Test the PCAP converter."""

    @patch('pcap2packetdrill.converter.rdpcap')
    def test_auto_detect_protocol(self, mock_rdpcap):
        """Test auto-detecting protocol from packets."""
        # Create a converter instance
        converter = PcapConverter("test.pcap")
        
        # Create mock packets
        tcp_packet = Mock()
        tcp_packet.haslayer = lambda x: x == 'IP' or x == 'TCP'
        
        udp_packet = Mock()
        udp_packet.haslayer = lambda x: x == 'IP' or x == 'UDP'
        
        # Set up the packets
        packets = [tcp_packet, tcp_packet, udp_packet]
        
        # Test auto-detection
        with patch.object(converter, '_auto_detect_protocol', return_value='tcp') as mock_detect:
            converter.convert()
            mock_detect.assert_called_once()
    
    @patch('pcap2packetdrill.converter.rdpcap')
    @patch('pcap2packetdrill.converter.jinja2.Environment')
    def test_convert_basic(self, mock_jinja, mock_rdpcap):
        """Test basic conversion flow."""
        # Set up mocks
        mock_rdpcap.return_value = [Mock()]
        
        # Mock template and rendering
        mock_template = Mock()
        mock_template.render.return_value = "TEST OUTPUT"
        mock_env = Mock()
        mock_env.get_template.return_value = mock_template
        mock_jinja.return_value = mock_env
        
        # Create converter instance
        converter = PcapConverter(
            pcap_file="test.pcap",
            protocol="tcp",
            client_ip="192.168.1.1",
            server_ip="192.168.1.2",
            client_port=12345,
            server_port=80,
        )
        
        # Mock filter_packets to return some data
        with patch.object(converter, '_filter_packets', return_value=[{"timestamp": 1.0}]) as mock_filter:
            with patch.object(converter, '_load_template', return_value=mock_template) as mock_load:
                with patch.object(converter.protocol_handler, 'format_packet', return_value="PACKET") as mock_format:
                    result = converter.convert()
                    
                    # Verify the flow
                    mock_rdpcap.assert_called_once_with("test.pcap")
                    mock_filter.assert_called_once()
                    mock_load.assert_called_once()
                    mock_template.render.assert_called_once()
                    self.assertEqual(result, "TEST OUTPUT")
    
    def test_adjust_timestamps(self):
        """Test timestamp adjustment."""
        converter = PcapConverter("test.pcap", relative_time=True)
        
        # Test with empty list
        self.assertEqual(converter._adjust_timestamps([]), [])
        
        # Test with timestamps
        packets_info = [
            {"timestamp": 10.0},
            {"timestamp": 11.5},
            {"timestamp": 13.0},
        ]
        
        adjusted = converter._adjust_timestamps(packets_info)
        
        self.assertEqual(adjusted[0]["timestamp"], 0.0)
        self.assertEqual(adjusted[1]["timestamp"], 1.5)
        self.assertEqual(adjusted[2]["timestamp"], 3.0)
        
        # Test with relative_time=False
        converter.relative_time = False
        non_adjusted = converter._adjust_timestamps(packets_info)
        
        self.assertEqual(non_adjusted[0]["timestamp"], 10.0)
        self.assertEqual(non_adjusted[1]["timestamp"], 11.5)
        self.assertEqual(non_adjusted[2]["timestamp"], 13.0)
        
    @patch('os.path.dirname')
    @patch('os.path.abspath')
    @patch('jinja2.Environment')
    @patch('jinja2.FileSystemLoader')
    def test_load_template(self, mock_loader, mock_env, mock_abspath, mock_dirname):
        """Test template loading."""
        # Set up mocks
        mock_abspath.return_value = "/path/to"
        mock_dirname.return_value = "/path"
        
        template_mock = Mock()
        env_mock = Mock()
        env_mock.get_template.return_value = template_mock
        mock_env.return_value = env_mock
        
        # Test with custom template
        converter = PcapConverter("test.pcap", protocol="tcp", template_file="/path/to/custom.j2")
        result = converter._load_template()
        
        mock_loader.assert_called_with("/path")
        mock_env.assert_called_once()
        env_mock.get_template.assert_called_once()
        self.assertEqual(result, template_mock)
        
        # Test with default template
        converter = PcapConverter("test.pcap", protocol="tcp")
        result = converter._load_template()
        
        self.assertEqual(result, template_mock)


if __name__ == "__main__":
    unittest.main()
