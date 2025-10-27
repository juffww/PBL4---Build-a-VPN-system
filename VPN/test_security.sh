#!/bin/bash

# VPN Security Test Suite
# Tests TLS handshake, encryption, and VPN connectivity

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVER_HOST="localhost"
SERVER_PORT=5000
UDP_PORT=5502
CERT_FILE="certs/server.crt"
KEY_FILE="certs/server.key"
TEST_LOG="test_results.log"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Helper functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

pass_test() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

check_requirements() {
    print_header "Checking Requirements"
    
    local missing=0
    
    # Check for required tools
    for cmd in openssl nc netcat timeout curl; do
        if ! command -v $cmd &> /dev/null; then
            print_fail "Missing command: $cmd"
            missing=1
        else
            print_pass "Found: $cmd"
        fi
    done
    
    # Check for Python (for advanced tests)
    if command -v python3 &> /dev/null; then
        print_pass "Found: python3"
    else
        print_info "Python3 not found (optional for advanced tests)"
    fi
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        print_fail "Please run as root (required for TUN interface)"
        missing=1
    else
        print_pass "Running as root"
    fi
    
    # Check certificate files
    if [ -f "$CERT_FILE" ]; then
        print_pass "Certificate file exists: $CERT_FILE"
    else
        print_fail "Certificate file not found: $CERT_FILE"
        missing=1
    fi
    
    if [ -f "$KEY_FILE" ]; then
        print_pass "Private key file exists: $KEY_FILE"
    else
        print_fail "Private key file not found: $KEY_FILE"
        missing=1
    fi
    
    # Check TUN module
    if lsmod | grep -q "^tun "; then
        print_pass "TUN module loaded"
    else
        print_info "Loading TUN module..."
        modprobe tun && print_pass "TUN module loaded" || print_fail "Failed to load TUN module"
    fi
    
    if [ $missing -eq 1 ]; then
        echo -e "\n${RED}Error: Missing requirements. Please install missing tools.${NC}"
        exit 1
    fi
    
    echo -e "\n${GREEN}All requirements met!${NC}"
}

test_certificate_validity() {
    print_header "Testing Certificate Validity"
    
    print_test "Verifying certificate format"
    if openssl x509 -in "$CERT_FILE" -noout -text &> /dev/null; then
        print_pass "Certificate is valid PEM format"
        pass_test 
    else
        print_fail "Certificate is invalid"
        fail_test 
        return 1
    fi
    
    print_test "Verifying private key format"
    if openssl rsa -in "$KEY_FILE" -check -noout &> /dev/null 2>&1; then
        print_pass "Private key is valid"
        pass_test  
    else
        print_fail "Private key is invalid"
        fail_test 
        return 1
    fi
    
    print_test "Checking certificate-key pair match"
    cert_modulus=$(openssl x509 -in "$CERT_FILE" -noout -modulus | md5sum)
    key_modulus=$(openssl rsa -in "$KEY_FILE" -noout -modulus | md5sum)
    
    if [ "$cert_modulus" = "$key_modulus" ]; then
        print_pass "Certificate and key pair match"
        pass_test  
    else
        print_fail "Certificate and key do not match"
        fail_test  
        return 1
    fi
    
    print_test "Checking certificate expiration"
    if openssl x509 -in "$CERT_FILE" -noout -checkend 86400 &> /dev/null; then
        print_pass "Certificate is valid for at least 24 hours"
        expiry=$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)
        print_info "Certificate expires: $expiry"
        pass_test  
    else
        print_fail "Certificate expires within 24 hours or is already expired"
        fail_test  
    fi
    
    echo "Subject: $(openssl x509 -in "$CERT_FILE" -noout -subject)"
    echo "Issuer: $(openssl x509 -in "$CERT_FILE" -noout -issuer)"
    echo "Valid from: $(openssl x509 -in "$CERT_FILE" -noout -startdate | cut -d= -f2)"
    echo "Valid until: $(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)"
}

test_tcp_connectivity() {
    print_header "Testing TCP Connectivity"

    print_test "Checking if server port is listening"
    if timeout 2 bash -c "echo > /dev/tcp/$SERVER_HOST/$SERVER_PORT" 2>/dev/null; then
        print_pass "Server is listening on port $SERVER_PORT"
        pass_test
    else
        print_fail "Cannot connect to server on port $SERVER_PORT"
        print_info "Make sure server is running: sudo ./vpn_server --cert $CERT_FILE --key $KEY_FILE --auto-start"
        fail_test
    fi
    
    print_test "Testing TCP connection establishment"
    response=$(timeout 3 bash -c "echo 'PING' | nc $SERVER_HOST $SERVER_PORT" 2>/dev/null || echo "")
    
    if [ -n "$response" ]; then
        print_pass "Received response from server"
        echo "Response: $response"
        pass_test
    else
        print_info "No immediate response (may require TLS handshake)"
    fi
}

test_tls_handshake() {
    print_header "Testing TLS Handshake"

    print_test "Testing TLS connection"
    output=$(echo | timeout 5 openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" -CAfile "$CERT_FILE" 2>&1)
    
    if echo "$output" | grep -q "Verify return code: 0"; then
        print_pass "TLS handshake successful with verification"
        pass_test
    elif echo "$output" | grep -q "SSL handshake has read"; then
        print_pass "TLS handshake completed (self-signed cert)"
        pass_test
    else
        print_fail "TLS handshake failed"
        echo "$output" | grep -E "(error|failed|Verify return code)" || echo "No specific error found"
        fail_test
    fi
    
    print_test "Checking TLS version"
    tls_version=$(echo "$output" | grep "Protocol" | head -1)
    #if echo "$tls_version" | grep -qE "TLSv1\.[2-3]"; then
    if echo "$output" | grep -qE "TLSv1\.[23]|TLS_AES_256_GCM"; then
        print_pass "Using secure TLS version: $tls_version"
        pass_test
    else
        print_fail "Insecure or unknown TLS version: $tls_version"
        fail_test
    fi
    
    print_test "Checking cipher suite"
    cipher=$(echo "$output" | grep "Cipher" | head -1)
    print_info "Cipher: $cipher"
    
    #if echo "$cipher" | grep -qE "(AES256|AES128)"; then
    if echo "$cipher" | grep -qE "(AES256|AES128|TLS_AES_256_GCM|TLS_CHACHA20)"; then
        print_pass "Using strong encryption cipher: $cipher"
        pass_test
    else
        print_fail "Weak or unknown cipher: $cipher"
        fail_test
    fi
    
    print_test "Testing certificate chain"
    if echo "$output" | grep -q "Certificate chain"; then
        print_pass "Certificate chain received"
        pass_test
    fi
}

test_protocol_commands() {
    print_header "Testing VPN Protocol Commands"

    print_test "Testing AUTH command over TLS"
    
    cat > /tmp/vpn_test_client.exp << 'EOF'
#!/usr/bin/expect -f
set timeout 20
set server [lindex $argv 0]
set port [lindex $argv 1]
set cert [lindex $argv 2]

# Khởi động OpenSSL client
spawn openssl s_client -connect $server:$port -CAfile $cert -quiet
expect {
    "WELCOME" { }
    timeout { exit 1 }
}

# Gửi AUTH
send "AUTH testuser testpass\r"
expect {
    "AUTH_OK" { }
    timeout { exit 1 }
}
sleep 1

# Gửi GET_STATUS
send "GET_STATUS\r"
expect {
    "STATUS" { }
    timeout { }
}
sleep 1

# Gửi PING
send "PING\r"
expect {
    "PONG" { 
        puts "\n\[TEST_MARKER\]PONG_RECEIVED"
    }
    timeout { 
        puts "\n\[TEST_MARKER\]PONG_TIMEOUT"
    }
}
sleep 1

# Ngắt kết nối đúng cách
send "DISCONNECT\r"
expect {
    "BYE" { }
    timeout { }
}
sleep 1

exit 0
EOF

    chmod +x /tmp/vpn_test_client.exp
    
    # Kiểm tra xem expect có cài không
    if ! command -v expect &> /dev/null; then
        print_info "Installing expect..."
        apt-get install -y expect &> /dev/null || yum install -y expect &> /dev/null
    fi
    
    response=$(timeout 25 /tmp/vpn_test_client.exp "$SERVER_HOST" "$SERVER_PORT" "$CERT_FILE" 2>&1 || echo "")
    
    echo "=== Full Response ===" 
    echo "$response"
    echo "===================="
    
    if echo "$response" | grep -q "AUTH_OK"; then
        print_pass "Authentication successful"
        #pass_test
    else
        print_fail "Authentication failed or no response"
        fail_test
    fi
    
    print_test "Checking VPN IP assignment" 
    if echo "$response" | grep -q "VPN_IP:10.8.0"; then
        vpn_ip=$(echo "$response" | grep -o 'VPN_IP:[0-9.]*' | head -1 | cut -d: -f2)
        print_pass "VPN IP assigned: $vpn_ip"
        pass_test
    else
        print_fail "VPN IP not assigned"
        fail_test
    fi
    
    print_test "Checking Client ID assignment"  
    if echo "$response" | grep -q "CLIENT_ID"; then
        client_id=$(echo "$response" | grep -o 'CLIENT_ID:[0-9]*' | head -1 | cut -d: -f2)
        print_pass "Client ID assigned: $client_id"
        pass_test
    else
        print_fail "Client ID not assigned"
        fail_test
    fi
    
    print_test "Checking UDP port information"  
    if echo "$response" | grep -q "UDP_PORT"; then
        print_pass "UDP port information received"
        pass_test
    else
        print_fail "UDP port info not received"
        fail_test
    fi
    
    print_test "Testing PING command"
    if echo "$response" | grep -q "PONG_RECEIVED"; then
        print_pass "PING command working"
        pass_test
    else
        print_fail "PING command failed"
        if echo "$response" | grep -q "PONG"; then
            print_info "PONG response found in output (timing issue)"
        else
            print_info "No PONG response received"
        fi
        fail_test
    fi
    
    rm -f /tmp/vpn_test_client.exp
}

test_udp_port() {
    print_header "Testing UDP Data Port"

    print_test "Checking if UDP port $UDP_PORT is accessible"
    
    # Send test UDP packet
    echo "TEST" | nc -u -w 1 "$SERVER_HOST" "$UDP_PORT" &> /dev/null
    
    if [ $? -eq 0 ]; then
        print_pass "UDP port $UDP_PORT is accessible"
        pass_test
    else
        print_info "UDP port test inconclusive (this is normal)"
    fi
}

test_encryption_strength() {
    print_header "Testing Encryption Strength"

    print_test "Verifying AES-256-GCM support in OpenSSL"
    #if openssl enc -ciphers | grep -qi "aes-256-gcm"; then
    if openssl list -cipher-algorithms | grep -qi "AES-256-GCM"; then
        print_pass "AES-256-GCM cipher available"
        pass_test
    else
        print_fail "AES-256-GCM cipher not available"
        fail_test
    fi
    
    print_test "Testing random number generation"
    random_data=$(openssl rand -hex 32)
    if [ ${#random_data} -eq 64 ]; then
        print_pass "32-byte random generation works"
        pass_test
    else
        print_fail "Random generation failed"
        fail_test
    fi
}

test_tun_interface() {
    print_header "Testing TUN Interface"

    print_test "Checking if tun0 interface exists"
    if ip link show tun0 &> /dev/null; then
        print_pass "tun0 interface exists"
        pass_test
        ip_addr=$(ip addr show tun0 | grep "inet " | awk '{print $2}')
        if [ -n "$ip_addr" ]; then
            print_pass "tun0 has IP address: $ip_addr"
            pass_test
        fi
        
        if ip link show tun0 | grep -q "UP"; then
            print_pass "tun0 interface is UP"
            pass_test
        else
            print_fail "tun0 interface is DOWN"
            fail_test
        fi
    else
        print_fail "tun0 interface not found (server may not be running)"
        fail_test
    fi
    
    print_test "Checking routing table for VPN subnet"
    if ip route | grep -q "10.8.0.0/24"; then
        print_pass "VPN subnet route exists"
        pass_test
        ip route | grep "10.8.0.0/24"
    else
        print_fail "VPN subnet route not found"
        fail_test
    fi
}

test_nat_rules() {
    print_header "Testing NAT/Firewall Rules"
    local test_failed=0

    print_test "Checking IP forwarding"
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        print_pass "IP forwarding is enabled"
        pass_test
    else
        print_fail "IP forwarding is disabled"
        fail_test
    fi
    
    print_test "Checking iptables NAT rules"
    if iptables -t nat -L POSTROUTING -n | grep -q "10.8.0.0/24"; then
        print_pass "NAT rule for VPN subnet exists"
        pass_test
    else
        print_fail "NAT rule not found"
        fail_test
    fi
    
    print_test "Checking iptables FORWARD rules"
    if iptables -L FORWARD -n | grep -q "10.8.0.0/24"; then
        print_pass "FORWARD rules for VPN exist"
        pass_test
    else
        print_info "FORWARD rules may not be set up yet"
        fail_test
    fi
}

stress_test() {
    print_header "Stress Testing (Optional)"
    
    read -p "Run stress test with multiple connections? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping stress test"
        return
    fi
    
    print_test "Testing multiple simultaneous TLS connections"
    
    local connections=10
    local tmpfile="/tmp/vpn_stress_$$.txt"
    > "$tmpfile"  # Tạo file rỗng
    
    for i in $(seq 1 $connections); do
        (
            if echo | timeout 5 openssl s_client -connect "$SERVER_HOST:$SERVER_PORT" \
               -CAfile "$CERT_FILE" 2>/dev/null | grep -q "Verify return code: 0"; then
                echo "SUCCESS" >> "$tmpfile"
            fi
        ) &
    done
    
    wait  # Chờ tất cả background jobs
    
    local success=$(wc -l < "$tmpfile" 2>/dev/null || echo 0)
    rm -f "$tmpfile"
    
    print_info "Successful connections: $success/$connections"
    
    if [ $success -ge $((connections * 80 / 100)) ]; then
        print_pass "Stress test passed (>80% success rate)"
        pass_test 
    else
        print_fail "Stress test failed (<80% success rate)"
        fail_test  
    fi
}

generate_report() {
    print_header "Test Summary"

    echo "Total Tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    
    local success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    echo "Success Rate: $success_rate%"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}✓ All tests passed! Your VPN server is secure and working correctly.${NC}"
    else
        echo -e "\n${YELLOW}⚠ Some tests failed. Please review the failures above.${NC}"
        test_failed=1
    fi
    
    # Save report
    {
        echo "VPN Security Test Report"
        echo "Generated: $(date)"
        echo "Server: $SERVER_HOST:$SERVER_PORT"
        echo "Total Tests: $TESTS_TOTAL"
        echo "Passed: $TESTS_PASSED"
        echo "Failed: $TESTS_FAILED"
        echo "Success Rate: $success_rate%"
    } > "$TEST_LOG"
    
    print_info "Full report saved to: $TEST_LOG"
}

# Main execution
main() {
    clear
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║   VPN Security Test Suite v2.0         ║"
    echo "║   Testing TLS + AES-256-GCM           ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_requirements
    
    test_certificate_validity
    test_tcp_connectivity
    test_tls_handshake
    test_protocol_commands
    test_udp_port
    test_encryption_strength
    test_tun_interface
    test_nat_rules
    stress_test
    
    generate_report
}

# Run main function
main "$@"