#!/usr/bin/env python3
"""
VPN Client Crypto Tester - FIXED VERSION
Tests TLS handshake, authentication, and UDP encryption
"""

import socket
import ssl
import struct
import os
import sys
import time
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class VPNTester:
    def __init__(self, server_host, server_port, cert_file):
        self.server_host = server_host
        self.server_port = server_port
        self.cert_file = cert_file
        self.client_id = None
        self.vpn_ip = None
        self.udp_key = None
        self.udp_port = 5502
        self.tx_counter = 0
        self.rx_counter = 0
        self.keep_alive = True  # ✅ Flag để giữ TLS connection alive
        
    def print_status(self, status_type, message):
        colors = {
            'INFO': '\033[0;34m',
            'SUCCESS': '\033[0;32m',
            'ERROR': '\033[0;31m',
            'WARN': '\033[1;33m'
        }
        print(f"{colors.get(status_type, '')}[{status_type}]\033[0m {message}")
    
    def create_tls_connection(self):
        """Create TLS connection to server"""
        self.print_status('INFO', f'Connecting to {self.server_host}:{self.server_port}')
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed certs
        
        # Create socket and wrap with TLS
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            self.tls_socket = context.wrap_socket(sock, server_hostname=self.server_host)
            self.tls_socket.connect((self.server_host, self.server_port))
            
            cipher = self.tls_socket.cipher()
            self.print_status('SUCCESS', f'TLS connected: {cipher[0]} ({cipher[1]})')
            
            # Receive welcome message
            welcome = self.tls_socket.recv(4096).decode('utf-8', errors='ignore')
            self.print_status('INFO', f'Server says: {welcome.strip()}')
            
            # ✅ START KEEP-ALIVE THREAD để giữ TLS connection
            self.start_keepalive_thread()
            
            return True
            
        except Exception as e:
            self.print_status('ERROR', f'TLS connection failed: {e}')
            return False
    
    def start_keepalive_thread(self):
        """Start background thread to keep TLS connection alive"""
        def keepalive_worker():
            self.print_status('INFO', 'Keep-alive thread started')
            while self.keep_alive:
                try:
                    time.sleep(10)
                    if self.keep_alive:
                        # Send PING to keep connection alive
                        self.tls_socket.sendall(b"PING\n")
                        # Read response (non-blocking)
                        self.tls_socket.settimeout(0.5)
                        try:
                            data = self.tls_socket.recv(1024)
                            if not data:
                                break
                        except socket.timeout:
                            pass
                        except:
                            break
                        finally:
                            self.tls_socket.settimeout(10)
                except:
                    break
            self.print_status('INFO', 'Keep-alive thread stopped')
        
        self.keepalive_thread = threading.Thread(target=keepalive_worker, daemon=True)
        self.keepalive_thread.start()
    
    def authenticate(self, username="testuser", password="testpass"):
        """Authenticate with server"""
        self.print_status('INFO', 'Authenticating...')
        
        try:
            # Send AUTH command
            auth_cmd = f"AUTH {username} {password}\n"
            self.tls_socket.sendall(auth_cmd.encode())
            
            # ✅ Wait a bit for server to process
            time.sleep(0.2)
            
            # Receive response
            response = self.tls_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if 'AUTH_OK' in response:
                self.print_status('SUCCESS', 'Authentication successful')
                
                # Parse response
                for part in response.split('|'):
                    if 'VPN_IP:' in part:
                        self.vpn_ip = part.split(':')[1]
                        self.print_status('SUCCESS', f'Assigned VPN IP: {self.vpn_ip}')
                    elif 'CLIENT_ID:' in part:
                        self.client_id = int(part.split(':')[1].strip())
                        self.print_status('SUCCESS', f'Client ID: {self.client_id}')
                    elif 'UDP_PORT:' in part:
                        self.udp_port = int(part.split(':')[1].strip())
                        self.print_status('INFO', f'UDP Port: {self.udp_port}')
                
                return True
            else:
                self.print_status('ERROR', f'Authentication failed: {response}')
                return False
                
        except Exception as e:
            self.print_status('ERROR', f'Authentication error: {e}')
            return False
    
    def request_udp_key(self):
        """Request UDP encryption key from server"""
        self.print_status('INFO', 'Requesting UDP encryption key...')
        
        try:
            # Send UDP_KEY_REQUEST
            self.tls_socket.sendall(b"UDP_KEY_REQUEST\n")
            
            # ✅ Wait for server to generate key
            time.sleep(0.3)
            
            # Receive response (UDP_KEY|<32 bytes key>\n)
            response = self.tls_socket.recv(4096)
            
            if response.startswith(b'UDP_KEY|'):
                # Extract 32-byte key
                key_start = response.index(b'|') + 1
                key_end = key_start + 32
                self.udp_key = response[key_start:key_end]
                
                if len(self.udp_key) == 32:
                    self.print_status('SUCCESS', f'UDP key received: {len(self.udp_key)} bytes')
                    self.print_status('INFO', f'Key (hex): {self.udp_key.hex()[:32]}...')
                    
                    # ✅ IMPORTANT: Give server time to setup crypto
                    self.print_status('INFO', 'Waiting for server crypto setup...')
                    time.sleep(0.5)
                    
                    return True
                else:
                    self.print_status('ERROR', f'Invalid key size: {len(self.udp_key)}')
                    return False
            else:
                self.print_status('ERROR', f'Key request failed: {response}')
                return False
                
        except Exception as e:
            self.print_status('ERROR', f'UDP key request error: {e}')
            return False
    
    def setup_udp_socket(self):
        """Setup UDP socket for data channel"""
        self.print_status('INFO', 'Setting up UDP socket...')
        
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.settimeout(5)  # ✅ Tăng timeout lên 5s
            
            # ✅ Retry UDP handshake up to 3 times
            for attempt in range(3):
                self.print_status('INFO', f'UDP handshake attempt {attempt + 1}/3')
                
                # Send handshake packet (ClientID, Size=0 for handshake)
                handshake = struct.pack('!II', self.client_id, 0)
                self.udp_socket.sendto(handshake, (self.server_host, self.udp_port))
                
                try:
                    # Wait for ACK
                    data, addr = self.udp_socket.recvfrom(1024)
                    if len(data) == 8:
                        recv_id, recv_size = struct.unpack('!II', data)
                        if recv_id == self.client_id and recv_size == 0:
                            self.print_status('SUCCESS', f'UDP handshake successful (attempt {attempt + 1})')
                            return True
                except socket.timeout:
                    if attempt < 2:
                        self.print_status('WARN', f'Timeout on attempt {attempt + 1}, retrying...')
                        time.sleep(0.5)
                    continue
            
            self.print_status('ERROR', 'UDP handshake failed after 3 attempts')
            return False
            
        except Exception as e:
            self.print_status('ERROR', f'UDP setup error: {e}')
            import traceback
            traceback.print_exc()
            return False
    
    def encrypt_packet(self, plaintext):
        """Encrypt packet using AES-256-GCM"""
        if not self.udp_key:
            raise Exception("UDP key not set")
        
        # Generate IV from counter
        iv = struct.pack('<Q', self.tx_counter) + b'\x00' * 4  # 12 bytes
        self.tx_counter += 1
        
        # Encrypt using AESGCM
        aesgcm = AESGCM(self.udp_key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        
        # ciphertext contains: encrypted_data + 16-byte tag
        tag = ciphertext[-16:]
        encrypted_data = ciphertext[:-16]
        
        # Format: [IV:12][Tag:16][Ciphertext:N]
        packet = iv + tag + encrypted_data
        
        return packet
    
    def decrypt_packet(self, packet):
        """Decrypt packet using AES-256-GCM"""
        if not self.udp_key or len(packet) < 28:
            return None
        
        # Parse packet
        iv = packet[:12]
        tag = packet[12:28]
        ciphertext = packet[28:]
        
        # Decrypt using AESGCM
        aesgcm = AESGCM(self.udp_key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
            return plaintext
        except Exception as e:
            self.print_status('ERROR', f'Decryption failed: {e}')
            return None
    
    def send_test_packet(self):
        """Send encrypted test packet via UDP"""
        self.print_status('INFO', 'Sending encrypted test packet...')
        
        try:
            # Create test IP packet (ICMP Echo Request to 8.8.8.8)
            test_data = b'\x45\x00\x00\x54' + os.urandom(80)  # Dummy IP packet
            
            # Encrypt
            encrypted = self.encrypt_packet(test_data)
            
            # Send via UDP: [ClientID:4][Size:4][EncryptedData]
            header = struct.pack('!II', self.client_id, len(encrypted))
            packet = header + encrypted
            
            self.udp_socket.sendto(packet, (self.server_host, self.udp_port))
            
            self.print_status('SUCCESS', f'Sent {len(packet)} bytes (encrypted)')
            self.print_status('INFO', f'Original: {len(test_data)} bytes → Encrypted: {len(encrypted)} bytes')
            
            return True
            
        except Exception as e:
            self.print_status('ERROR', f'Send error: {e}')
            return False
    
    def test_ping(self):
        """Test PING command"""
        self.print_status('INFO', 'Testing PING...')
        
        try:
            self.tls_socket.sendall(b"PING\n")
            time.sleep(0.2)
            response = self.tls_socket.recv(1024).decode('utf-8', errors='ignore')
            
            if 'PONG' in response:
                self.print_status('SUCCESS', f'PONG received: {response.strip()}')
                return True
            else:
                self.print_status('ERROR', f'Unexpected response: {response}')
                return False
                
        except Exception as e:
            self.print_status('ERROR', f'PING error: {e}')
            return False
    
    def test_status(self):
        """Test GET_STATUS command"""
        self.print_status('INFO', 'Getting status...')
        
        try:
            self.tls_socket.sendall(b"GET_STATUS\n")
            time.sleep(0.2)
            response = self.tls_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if 'STATUS|' in response:
                self.print_status('SUCCESS', f'Status: {response.strip()}')
                return True
            else:
                self.print_status('ERROR', f'Status error: {response}')
                return False
                
        except Exception as e:
            self.print_status('ERROR', f'Status error: {e}')
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        self.print_status('INFO', 'Disconnecting...')
        
        try:
            # ✅ Stop keep-alive first
            self.keep_alive = False
            time.sleep(0.5)
            
            if hasattr(self, 'tls_socket'):
                self.tls_socket.sendall(b"DISCONNECT\n")
                time.sleep(0.5)
                self.tls_socket.close()
            
            if hasattr(self, 'udp_socket'):
                self.udp_socket.close()
            
            self.print_status('SUCCESS', 'Disconnected')
            
        except Exception as e:
            self.print_status('WARN', f'Disconnect error: {e}')
    
    def run_full_test(self):
        """Run complete test suite"""
        print("\n" + "="*50)
        print("VPN Crypto Client Tester - FIXED")
        print("="*50 + "\n")
        
        success_count = 0
        total_tests = 8
        
        # Test 1: TLS Connection
        if self.create_tls_connection():
            success_count += 1
        else:
            return
        
        time.sleep(0.5)
        
        # Test 2: Authentication
        if self.authenticate():
            success_count += 1
        else:
            return
        
        time.sleep(0.5)
        
        # Test 3: UDP Key Exchange
        if self.request_udp_key():
            success_count += 1
        else:
            return
        
        time.sleep(0.5)
        
        # Test 4: UDP Setup
        if self.setup_udp_socket():
            success_count += 1
        else:
            return
        
        time.sleep(0.5)
        
        # Test 5: Encryption test
        self.print_status('INFO', 'Testing encryption...')
        try:
            test_data = b"Hello VPN Server!" * 10
            encrypted = self.encrypt_packet(test_data)
            decrypted = self.decrypt_packet(encrypted)
            
            if decrypted == test_data:
                self.print_status('SUCCESS', 'Encryption/Decryption working correctly')
                success_count += 1
            else:
                self.print_status('ERROR', 'Encryption/Decryption mismatch')
        except Exception as e:
            self.print_status('ERROR', f'Encryption test failed: {e}')
        
        time.sleep(0.5)
        
        # Test 6: Send encrypted packet
        if self.send_test_packet():
            success_count += 1
        
        time.sleep(0.5)
        
        # Test 7: PING
        if self.test_ping():
            success_count += 1
        
        time.sleep(0.5)
        
        # Test 8: Status
        if self.test_status():
            success_count += 1
        
        # Summary
        print("\n" + "="*50)
        print(f"Test Results: {success_count}/{total_tests} passed")
        print("="*50 + "\n")
        
        if success_count == total_tests:
            self.print_status('SUCCESS', '✓ All tests passed! VPN crypto is working correctly.')
        elif success_count >= total_tests * 0.7:
            self.print_status('WARN', '⚠ Most tests passed, but some issues detected.')
        else:
            self.print_status('ERROR', '✗ Multiple tests failed. Check server configuration.')
        
        # Cleanup
        self.disconnect()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 test_python_security.py <server_host> [server_port] [cert_file]")
        print("Example: python3 test_python_security.py localhost 5000 certs/server.crt")
        sys.exit(1)
    
    server_host = sys.argv[1]
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    cert_file = sys.argv[3] if len(sys.argv) > 3 else "certs/server.crt"
    
    tester = VPNTester(server_host, server_port, cert_file)
    tester.run_full_test()


if __name__ == "__main__":
    main()