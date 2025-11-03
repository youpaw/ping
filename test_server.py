#!/usr/bin/env python3
"""
ICMP Test Server - Fabricated Response Generator

This server intercepts ICMP Echo Requests and responds with fabricated ICMP messages
cycling through different message types in round-robin fashion.

Key Features:
- Uses raw sockets to bypass kernel ICMP processing
- Manually fabricates all ICMP responses with proper checksums
- Supports IPv4 only
- Each request gets a different response type in sequence

Usage:
    sudo python3 icmp_test_server.py [interface]
    
Examples:
    sudo python3 icmp_test_server.py lo       # Listen on localhost
    sudo python3 icmp_test_server.py eth0     # Listen on eth0

Requirements:
    - Root privileges (for raw sockets)
    - python3

The server intercepts packets before the kernel processes them.
"""

import sys
import time
import socket
import struct
import signal

class ICMPTestServer:
    def __init__(self, bind_ip='127.0.0.1'):
        self.bind_ip = bind_ip
        self.response_index = 0
        self.running = True
        
        # List of different ICMP responses to cycle through
        self.responses = [
            {'type': 0, 'code': 0, 'name': 'Echo Reply (Normal)'},
            {'type': 3, 'code': 0, 'name': 'Destination Unreachable - Network Unreachable'},
            {'type': 3, 'code': 1, 'name': 'Destination Unreachable - Host Unreachable'},
            {'type': 3, 'code': 2, 'name': 'Destination Unreachable - Protocol Unreachable'},
            {'type': 3, 'code': 3, 'name': 'Destination Unreachable - Port Unreachable'},
            {'type': 3, 'code': 4, 'name': 'Destination Unreachable - Fragmentation Needed'},
            {'type': 3, 'code': 9, 'name': 'Destination Unreachable - Network Prohibited'},
            {'type': 3, 'code': 10, 'name': 'Destination Unreachable - Host Prohibited'},
            {'type': 3, 'code': 13, 'name': 'Destination Unreachable - Communication Prohibited'},
            {'type': 4, 'code': 0, 'name': 'Source Quench (deprecated)'},
            {'type': 5, 'code': 0, 'name': 'Redirect - Network'},
            {'type': 5, 'code': 1, 'name': 'Redirect - Host'},
            {'type': 11, 'code': 0, 'name': 'Time Exceeded - TTL exceeded in transit'},
            {'type': 11, 'code': 1, 'name': 'Time Exceeded - Fragment reassembly time exceeded'},
            {'type': 12, 'code': 0, 'name': 'Parameter Problem - Pointer indicates error'},
            {'type': 12, 'code': 1, 'name': 'Parameter Problem - Missing required option'},
        ]
        
        print(f"ICMP Test Server starting on {bind_ip}")
        print(f"Will cycle through {len(self.responses)} different ICMP response types:\n")
        for i, resp in enumerate(self.responses):
            print(f"  {i+1}. Type {resp['type']}, Code {resp['code']}: {resp['name']}")
        print("\nListening for ICMP Echo Requests...\n")
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\nShutting down ICMP Test Server...")
        self.running = False
        sys.exit(0)
    
    def checksum(self, data):
        """Calculate IP/ICMP checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
        
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        
        return ~s & 0xffff
    
    def create_ip_header(self, src_ip, dst_ip, payload_len):
        """Create IP header"""
        version_ihl = (4 << 4) + 5  # IPv4, header length 5*4=20 bytes
        tos = 0
        total_len = 20 + payload_len  # IP header + payload
        identification = 54321
        flags_fragment = 0
        ttl = 64
        protocol = 1  # ICMP
        checksum = 0  # Will be calculated
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        
        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_len, identification,
            flags_fragment, ttl, protocol, checksum,
            src, dst
        )
        
        # Calculate checksum
        checksum = self.checksum(header)
        
        # Recreate header with checksum
        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_len, identification,
            flags_fragment, ttl, protocol, checksum,
            src, dst
        )
        
        return header
    
    def create_icmp_echo_reply(self, icmp_id, icmp_seq, payload):
        """Create ICMP Echo Reply"""
        icmp_type = 0  # Echo Reply
        icmp_code = 0
        checksum = 0
        
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        checksum = self.checksum(header + payload)
        
        header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        
        return header + payload
    
    def create_icmp_error(self, error_type, error_code, original_ip_header, original_icmp_data):
        """Create ICMP error message (Dest Unreachable, Time Exceeded, etc.)"""
        icmp_type = error_type
        icmp_code = error_code
        checksum = 0
        unused = 0  # 4 bytes unused (or used for specific error info)
        
        # ICMP error messages contain the original IP header + first 8 bytes of original data
        original_data = original_ip_header + original_icmp_data[:8]
        
        header = struct.pack('!BBHI', icmp_type, icmp_code, checksum, unused)
        checksum = self.checksum(header + original_data)
        
        header = struct.pack('!BBHI', icmp_type, icmp_code, checksum, unused)
        
        return header + original_data
    
    def handle_echo_request(self, recv_socket, send_socket, data, addr):
        """Process ICMP Echo Request and send appropriate response"""
        # Parse IP header
        ip_header = data[:20]
        ip_header_unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header)
        src_ip = socket.inet_ntoa(ip_header_unpacked[8])
        dst_ip = socket.inet_ntoa(ip_header_unpacked[9])
        
        # Parse ICMP header
        icmp_header = data[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
        
        # Only process Echo Requests
        if icmp_type != 8:
            return
        
        # Get ICMP payload
        icmp_payload = data[28:]
        
        # Get current response type
        resp_info = self.responses[self.response_index]
        resp_type = resp_info['type']
        resp_code = resp_info['code']
        resp_name = resp_info['name']
        
        print(f"[{time.strftime('%H:%M:%S')}] Received Echo Request from {src_ip} (id={icmp_id}, seq={icmp_seq})")
        print(f"  -> Responding with: {resp_name}")
        
        # Create ICMP response
        if resp_type == 0:
            # Echo Reply
            icmp_packet = self.create_icmp_echo_reply(icmp_id, icmp_seq, icmp_payload)
        else:
            # Error message
            icmp_packet = self.create_icmp_error(resp_type, resp_code, ip_header, data[20:])
        
        # Create IP packet
        ip_packet = self.create_ip_header(dst_ip, src_ip, len(icmp_packet))
        full_packet = ip_packet + icmp_packet
        
        # Send response
        try:
            send_socket.sendto(full_packet, (src_ip, 0))
        except Exception as e:
            print(f"  -> Error sending response: {e}")
        
        # Move to next response type
        self.response_index = (self.response_index + 1) % len(self.responses)
        print()
    
    def run(self):
        """Start listening for ICMP Echo Requests"""
        try:
            # Create raw socket for receiving
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_socket.bind((self.bind_ip, 0))
            recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            
            # Create raw socket for sending with IP_HDRINCL
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Set timeout to allow checking running flag
            recv_socket.settimeout(1.0)
            
            while self.running:
                try:
                    data, addr = recv_socket.recvfrom(65565)
                    self.handle_echo_request(recv_socket, send_socket, data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"Error processing packet: {e}")
                    
        except PermissionError:
            print("Error: This script requires root privileges to use raw sockets.")
            print("Please run with sudo: sudo python3 icmp_test_server.py")
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
        finally:
            try:
                recv_socket.close()
                send_socket.close()
            except:
                pass

def main():
    if len(sys.argv) > 1:
        bind_ip = sys.argv[1]
    else:
        bind_ip = '127.0.0.1'
    
    try:
        server = ICMPTestServer(bind_ip=bind_ip)
        server.run()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

if __name__ == '__main__':
    main()

