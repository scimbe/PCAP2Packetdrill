"""
Tests for the flow analyzer module.

This module contains unit tests for the FlowAnalyzer class, which is
responsible for identifying complete connection cycles in PCAP files.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock

from scapy.all import Ether, IP, TCP, UDP, Raw

# Use the same try/except pattern for SCTP imports
try:
    from scapy.contrib.sctp import SCTP, SCTPChunk
except ImportError:
    # Create dummy SCTP classes for testing
    class SCTP:
        """Dummy SCTP class for when scapy.contrib.sctp is not available."""
        pass
    
    class SCTPChunk:
        """Dummy SCTPChunk class for when scapy.contrib.sctp is not available."""
        pass

from pcap2packetdrill.flow_analyzer import FlowAnalyzer


class TestFlowAnalyzer(unittest.TestCase):
    """Test cases for the FlowAnalyzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = FlowAnalyzer(debug=False)
        
        # Define some common test values
        self.client_ip = "192.168.1.1"
        self.server_ip = "192.168.1.2"
        self.client_port = 12345
        self.server_port = 80
    
    def test_get_flow_id(self):
        """Test flow ID generation."""
        # Test with TCP protocol
        flow_id = self.analyzer.get_flow_id(
            "tcp", self.client_ip, self.server_ip, self.client_port, self.server_port
        )
        self.assertIsInstance(flow_id, str)
        self.assertTrue(flow_id.startswith("tcp:"))
        
        # Test with UDP protocol
        flow_id = self.analyzer.get_flow_id(
            "udp", self.client_ip, self.server_ip, self.client_port, self.server_port
        )
        self.assertIsInstance(flow_id, str)
        self.assertTrue(flow_id.startswith("udp:"))
        
        # Test with SCTP protocol
        flow_id = self.analyzer.get_flow_id(
            "sctp", self.client_ip, self.server_ip, self.client_port, self.server_port
        )
        self.assertIsInstance(flow_id, str)
        self.assertTrue(flow_id.startswith("sctp:"))
        
        # Test that the same flow gets the same ID regardless of direction
        forward_id = self.analyzer.get_flow_id(
            "tcp", self.client_ip, self.server_ip, self.client_port, self.server_port
        )
        reverse_id = self.analyzer.get_flow_id(
            "tcp", self.server_ip, self.client_ip, self.server_port, self.client_port
        )
        self.assertEqual(forward_id, reverse_id)
    
    def test_parse_flow_id(self):
        """Test parsing a flow ID into its components."""
        # Create a flow ID
        flow_id = self.analyzer.get_flow_id(
            "tcp", self.client_ip, self.server_ip, self.client_port, self.server_port
        )
        
        # Parse it back
        protocol, src_ip, dst_ip, src_port, dst_port = self.analyzer.parse_flow_id(flow_id)
        
        # Verify the parsed components
        self.assertEqual(protocol, "tcp")
        self.assertIn(src_ip, [self.client_ip, self.server_ip])
        self.assertIn(dst_ip, [self.client_ip, self.server_ip])
        self.assertIn(src_port, [self.client_port, self.server_port])
        self.assertIn(dst_port, [self.client_port, self.server_port])
    
    def _create_tcp_packet(self, src_ip, dst_ip, src_port, dst_port, flags, seq=0, ack=0, payload=b""):
        """Create a TCP packet for testing."""
        packet = (
            Ether() / 
            IP(src=src_ip, dst=dst_ip) / 
            TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)
        )
        
        if payload:
            packet = packet / Raw(payload)
            
        # Add timestamp to packet
        packet.time = 0.0
        
        return packet
    
    def test_identify_flows(self):
        """Test identifying flows from a list of packets."""
        # Create some test packets
        tcp_packet = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, "S"
        )
        
        udp_packet = (
            Ether() / 
            IP(src=self.client_ip, dst=self.server_ip) / 
            UDP(sport=self.client_port, dport=self.server_port) /
            Raw(b"UDP payload")
        )
        udp_packet.time = 0.0
        
        # Mock SCTP packet since we might not have real SCTP support
        sctp_packet = Mock()
        sctp_packet.time = 0.0
        # Set up mock behavior for SCTP packet
        sctp_packet.__contains__ = lambda self, layer: layer in [IP, SCTP]
        sctp_packet.get = lambda layer, default=None: default
        sctp_packet.__getitem__ = lambda self, layer: {
            IP: MagicMock(src=self.client_ip, dst=self.server_ip),
            SCTP: MagicMock(sport=self.client_port, dport=self.server_port)
        }[layer]
        
        # Test with a set of mixed packets
        packets = [tcp_packet, udp_packet, sctp_packet]
        
        # Mock the necessary methods to handle SCTP packets
        with patch.object(self.analyzer, 'get_flow_id') as mock_get_flow_id:
            # Set up the mock to return different flow IDs for different protocols
            mock_get_flow_id.side_effect = lambda proto, src_ip, dst_ip, src_port, dst_port: f"{proto}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            flows = self.analyzer.identify_flows(packets)
            
            # Verify that get_flow_id was called for each packet
            self.assertEqual(mock_get_flow_id.call_count, len(packets))
            
            # Verify that we got a flow for each packet
            self.assertEqual(len(flows), 3)
    
    def test_extract_tcp_connection_cycles(self):
        """Test extracting complete TCP connection cycles."""
        # Create a complete TCP connection cycle
        # SYN
        syn = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "S", seq=100, ack=0
        )
        syn.time = 1.0
        
        # SYN-ACK
        syn_ack = self._create_tcp_packet(
            self.server_ip, self.client_ip, self.server_port, self.client_port, 
            "SA", seq=200, ack=101
        )
        syn_ack.time = 1.1
        
        # ACK (handshake completion)
        ack = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "A", seq=101, ack=201
        )
        ack.time = 1.2
        
        # Data from client
        client_data = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "PA", seq=101, ack=201, payload=b"Hello server"
        )
        client_data.time = 1.3
        
        # ACK from server
        server_ack = self._create_tcp_packet(
            self.server_ip, self.client_ip, self.server_port, self.client_port, 
            "A", seq=201, ack=113
        )
        server_ack.time = 1.4
        
        # Data from server
        server_data = self._create_tcp_packet(
            self.server_ip, self.client_ip, self.server_port, self.client_port, 
            "PA", seq=201, ack=113, payload=b"Hello client"
        )
        server_data.time = 1.5
        
        # ACK from client
        client_ack = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "A", seq=113, ack=213
        )
        client_ack.time = 1.6
        
        # FIN from client
        client_fin = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "FA", seq=113, ack=213
        )
        client_fin.time = 1.7
        
        # ACK from server
        fin_ack = self._create_tcp_packet(
            self.server_ip, self.client_ip, self.server_port, self.client_port, 
            "A", seq=213, ack=114
        )
        fin_ack.time = 1.8
        
        # FIN from server
        server_fin = self._create_tcp_packet(
            self.server_ip, self.client_ip, self.server_port, self.client_port, 
            "FA", seq=213, ack=114
        )
        server_fin.time = 1.9
        
        # Final ACK from client
        final_ack = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "A", seq=114, ack=214
        )
        final_ack.time = 2.0
        
        # Test with an unordered packet list
        packets = [
            ack, syn, syn_ack, client_data, server_ack, server_data,
            client_ack, client_fin, fin_ack, server_fin, final_ack
        ]
        
        cycles = self.analyzer._extract_tcp_connection_cycles(packets)
        
        # Should find exactly one complete connection cycle
        self.assertEqual(len(cycles), 1)
        self.assertEqual(len(cycles[0]), 11)  # All packets should be included
    
    @unittest.skip("SCTP testing requires more complex setup")
    def test_extract_sctp_association_cycles(self):
        """Test extracting complete SCTP association cycles."""
        # This would require more complex packet creation with valid SCTP chunks
        # For simplicity, this test is skipped for now
        pass


if __name__ == "__main__":
    unittest.main()
