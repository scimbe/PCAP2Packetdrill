"""Tests for the protocol handlers."""

import unittest
from unittest.mock import Mock, patch

from scapy.all import Ether, IP, TCP, UDP, SCTP, Raw
from pcap2packetdrill.protocols import TCPHandler, UDPHandler, SCTPHandler


class TestTCPHandler(unittest.TestCase):
    """Test the TCP protocol handler."""

    def setUp(self):
        """Set up the test case."""
        self.handler = TCPHandler()
        
        # Create a sample TCP packet
        self.tcp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / \
                          TCP(sport=12345, dport=80, seq=100, ack=200, flags="PA", window=8192) / \
                          Raw(b"GET / HTTP/1.1\r\n")
        self.tcp_packet.time = 1.0  # Add timestamp
        
    def test_extract_packet_info(self):
        """Test extracting information from a TCP packet."""
        info = self.handler.extract_packet_info(self.tcp_packet)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "192.168.1.1")
        self.assertEqual(info["dst_ip"], "192.168.1.2")
        self.assertEqual(info["src_port"], 12345)
        self.assertEqual(info["dst_port"], 80)
        self.assertEqual(info["seq"], 100)
        self.assertEqual(info["ack"], 200)
        self.assertEqual(info["flags"], 24)  # "PA" = PSH(8) + ACK(16) = 24
        self.assertEqual(info["win"], 8192)
        self.assertEqual(info["payload"], b"GET / HTTP/1.1\r\n")
        
    def test_format_packet(self):
        """Test formatting a TCP packet as a packetdrill command."""
        info = {
            "timestamp": 1.0,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "src_port": 12345,
            "dst_port": 80,
            "seq": 100,
            "ack": 200,
            "flags": 24,  # "PA"
            "win": 8192,
            "payload": b"GET / HTTP/1.1\r\n",
            "options": [],
        }
        
        formatted = self.handler.format_packet(info)
        
        self.assertIn("1.000000", formatted)
        self.assertIn("192.168.1.1:12345 -->", formatted)
        self.assertIn("192.168.1.2:80", formatted)
        self.assertIn("tcp PA", formatted)
        self.assertIn("seq 100", formatted)
        self.assertIn("ack 200", formatted)
        self.assertIn("win 8192", formatted)
        
    def test_identify_endpoints(self):
        """Test identifying client and server endpoints."""
        # Create a SYN packet first
        syn_packet_info = {
            "timestamp": 0.5,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "src_port": 12345,
            "dst_port": 80,
            "seq": 50,
            "ack": 0,
            "flags": 2,  # SYN
            "win": 8192,
            "payload": b"",
            "options": [],
        }
        
        packets_info = [syn_packet_info]
        
        client_ip, client_port, server_ip, server_port = self.handler.identify_endpoints(packets_info)
        
        self.assertEqual(client_ip, "192.168.1.1")
        self.assertEqual(client_port, 12345)
        self.assertEqual(server_ip, "192.168.1.2")
        self.assertEqual(server_port, 80)


class TestUDPHandler(unittest.TestCase):
    """Test the UDP protocol handler."""

    def setUp(self):
        """Set up the test case."""
        self.handler = UDPHandler()
        
        # Create a sample UDP packet
        self.udp_packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / \
                          UDP(sport=12345, dport=53) / \
                          Raw(b"DNS query")
        self.udp_packet.time = 1.0  # Add timestamp
        
    def test_extract_packet_info(self):
        """Test extracting information from a UDP packet."""
        info = self.handler.extract_packet_info(self.udp_packet)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "192.168.1.1")
        self.assertEqual(info["dst_ip"], "192.168.1.2")
        self.assertEqual(info["src_port"], 12345)
        self.assertEqual(info["dst_port"], 53)
        self.assertEqual(info["payload"], b"DNS query")
        
    def test_format_packet(self):
        """Test formatting a UDP packet as a packetdrill command."""
        info = {
            "timestamp": 1.0,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "src_port": 12345,
            "dst_port": 53,
            "payload": b"DNS query",
        }
        
        formatted = self.handler.format_packet(info)
        
        self.assertIn("1.000000", formatted)
        self.assertIn("192.168.1.1:12345 -->", formatted)
        self.assertIn("192.168.1.2:53", formatted)
        self.assertIn("udp", formatted)
        self.assertIn("0x", formatted)  # Hex payload
        
    def test_identify_endpoints(self):
        """Test identifying client and server endpoints."""
        packets_info = [{
            "timestamp": 1.0,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "src_port": 12345,
            "dst_port": 53,
            "payload": b"DNS query",
        }]
        
        client_ip, client_port, server_ip, server_port = self.handler.identify_endpoints(packets_info)
        
        self.assertEqual(client_ip, "192.168.1.1")
        self.assertEqual(client_port, 12345)
        self.assertEqual(server_ip, "192.168.1.2")
        self.assertEqual(server_port, 53)


if __name__ == "__main__":
    unittest.main()
