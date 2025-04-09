"""
Tests for the flow analyzer module.

This module contains unit tests for the FlowAnalyzer class, which is
responsible for identifying complete connection cycles in PCAP files.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock

from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.contrib.sctp import SCTP, SCTPChunk
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
        
        # Test validation
        with self.assertRaises(ValueError):
            self.analyzer.get_flow_id("invalid", self.client_ip, self.server_ip, self.client_port, self.server_port)
            
        with self.assertRaises(ValueError):
            self.analyzer.get_flow_id("tcp", "invalid-ip", self.server_ip, self.client_port, self.server_port)
            
        with self.assertRaises(ValueError):
            self.analyzer.get_flow_id("tcp", self.client_ip, self.server_ip, 70000, self.server_port)
    
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
        
        # Test invalid flow ID
        with self.assertRaises(ValueError):
            self.analyzer.parse_flow_id("invalid-flow-id")
    
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
        
        # Test with empty packet list
        with self.assertRaises(ValueError):
            self.analyzer.identify_flows([])
        
        # Test with a single TCP packet
        flows = self.analyzer.identify_flows([tcp_packet])
        self.assertEqual(len(flows), 1)
        
        # Test with mixed packets
        flows = self.analyzer.identify_flows([tcp_packet, udp_packet])
        self.assertEqual(len(flows), 2)
        
        # Check that packets are assigned to the correct flows
        for flow_id, packets in flows.items():
            if "tcp" in flow_id:
                self.assertEqual(len(packets), 1)
                self.assertTrue(TCP in packets[0])
            elif "udp" in flow_id:
                self.assertEqual(len(packets), 1)
                self.assertTrue(UDP in packets[0])
    
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
        
        # Test with incomplete connection (handshake only)
        incomplete = [syn, syn_ack, ack]
        cycles = self.analyzer._extract_tcp_connection_cycles(incomplete)
        self.assertEqual(len(cycles), 0)  # No complete cycles (though established)
        
        # Test with connection terminated by RST
        # Create connection with RST
        rst_packets = [syn, syn_ack, ack, client_data, server_ack]
        
        # Add RST packet
        rst = self._create_tcp_packet(
            self.client_ip, self.server_ip, self.client_port, self.server_port, 
            "R", seq=113, ack=201
        )
        rst.time = 1.7
        rst_packets.append(rst)
        
        cycles = self.analyzer._extract_tcp_connection_cycles(rst_packets)
        self.assertEqual(len(cycles), 1)  # RST terminated connection is complete
        self.assertEqual(len(cycles[0]), 6)  # All packets should be included
    
    def _create_sctp_packet(self, src_ip, dst_ip, src_port, dst_port, chunk_type, tag=0):
        """Create an SCTP packet with a specific chunk type for testing."""
        # Create a chunk of the specified type
        chunk = SCTPChunk(type=chunk_type)
        
        # Set up SCTP packet
        packet = (
            Ether() / 
            IP(src=src_ip, dst=dst_ip) / 
            SCTP(sport=src_port, dport=dst_port, tag=tag)
        )
        
        # Add the chunk
        packet[SCTP].chunks = [chunk]
        
        # Add timestamp to packet
        packet.time = 0.0
        
        return packet
    
    @unittest.skip("SCTP testing requires more complex setup")
    def test_extract_sctp_association_cycles(self):
        """Test extracting complete SCTP association cycles."""
        # This would require more complex packet creation with valid SCTP chunks
        # For simplicity, this test is skipped for now
        pass


if __name__ == "__main__":
    unittest.main()
