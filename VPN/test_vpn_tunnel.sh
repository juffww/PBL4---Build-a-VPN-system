#!/bin/bash

# VPN Tunnel Test Script
# Tự động tạo TUN interface và test traffic

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

function print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

function setup_test_environment() {
    print_info "Setting up test environment..."
    
    # Load TUN module
    modprobe tun
    
    # Create TUN interface manually for testing
    ip tuntap add dev tun-test mode tun
    ip addr add 10.8.0.1/24 dev tun-test
    ip link set tun-test up
    
    # Add route
    ip route add 10.8.0.0/24 dev tun-test 2>/dev/null || true
    
    # Setup NAT
    DEFAULT_IF=$(ip route show default | head -n1 | awk '{print $5}')
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_IF -j MASQUERADE
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -d 10.8.0.0/24 -j ACCEPT
    
    print_info "Test environment setup complete"
    print_info "TUN interface: tun-test (10.8.0.1/24)"
    print_info "Default interface: $DEFAULT_IF"
}

function test_tun_interface() {
    print_info "Testing TUN interface..."
    
    # Show interface status
    echo -e "${YELLOW}Interface Status:${NC}"
    ip addr show tun-test
    echo
    
    # Test ping to TUN interface
    echo -e "${YELLOW}Testing ping to TUN interface:${NC}"
    ping -c 3 10.8.0.1
    echo
    
    # Show routing
    echo -e "${YELLOW}Routing table:${NC}"
    ip route show | grep "10.8.0"
    echo
}

function simulate_client_traffic() {
    print_info "Simulating client traffic..."
    
    # Create network namespace for client simulation
    ip netns add vpn-client 2>/dev/null || true
    
    # Create veth pair
    ip link add veth-client type veth peer name veth-server
    
    # Move client end to namespace
    ip link set veth-client netns vpn-client
    
    # Configure server end
    ip addr add 10.8.0.1/30 dev veth-server
    ip link set veth-server up
    
    # Configure client end in namespace
    ip netns exec vpn-client ip addr add 10.8.0.2/30 dev veth-client
    ip netns exec vpn-client ip link set veth-client up
    ip netns exec vpn-client ip link set lo up
    
    # Add routes in client namespace
    ip netns exec vpn-client ip route add default via 10.8.0.1
    
    # Test from client namespace
    echo -e "${YELLOW}Testing from client namespace:${NC}"
    ip netns exec vpn-client ping -c 3 10.8.0.1
    
    echo -e "${YELLOW}Testing internet connectivity from client:${NC}"
    ip netns exec vpn-client ping -c 3 8.8.8.8 || print_warn "Internet connectivity test failed"
    
    print_info "Client traffic simulation complete"
}

function monitor_traffic() {
    print_info "Monitoring traffic (10 seconds)..."
    
    # Start traffic monitoring in background
    {
        while true; do
            RX=$(cat /sys/class/net/tun-test/statistics/rx_bytes 2>/dev/null || echo "0")
            TX=$(cat /sys/class/net/tun-test/statistics/tx_bytes 2>/dev/null || echo "0")
            printf "\rTUN Traffic - RX: %10s bytes, TX: %10s bytes" "$RX" "$TX"
            sleep 1
        done
    } &
    MONITOR_PID=$!
    
    # Generate some test traffic
    ping -c 10 -i 0.5 10.8.0.1 >/dev/null 2>&1 &
    
    sleep 10
    kill $MONITOR_PID 2>/dev/null
    echo
    
    # Show final statistics
    echo -e "${YELLOW}Final Statistics:${NC}"
    cat /sys/class/net/tun-test/statistics/rx_bytes 2>/dev/null | xargs echo "RX Bytes:"
    cat /sys/class/net/tun-test/statistics/tx_bytes 2>/dev/null | xargs echo "TX Bytes:"
    cat /sys/class/net/tun-test/statistics/rx_packets 2>/dev/null | xargs echo "RX Packets:"
    cat /sys/class/net/tun-test/statistics/tx_packets 2>/dev/null | xargs echo "TX Packets:"
}

function test_packet_capture() {
    print_info "Testing packet capture on TUN interface..."
    
    if command -v tcpdump &> /dev/null; then
        echo -e "${YELLOW}Capturing packets (5 seconds):${NC}"
        timeout 5 tcpdump -i tun-test -n -c 10 2>/dev/null || print_warn "No packets captured"
    else
        print_warn "tcpdump not available, skipping packet capture"
    fi
    echo
}

function test_nat_functionality() {
    print_info "Testing NAT functionality..."
    
    # Check iptables rules
    echo -e "${YELLOW}Current NAT rules:${NC}"
    iptables -t nat -L POSTROUTING -n | grep "10.8.0.0/24"
    
    echo -e "${YELLOW}Forward rules:${NC}"
    iptables -L FORWARD -n | grep "10.8.0.0/24"
    
    # Test actual NAT
    if ip netns list | grep -q vpn-client; then
        echo -e "${YELLOW}Testing NAT with external ping:${NC}"
        ip netns exec vpn-client timeout 5 ping -c 3 8.8.8.8 && print_info "NAT working" || print_warn "NAT may not be working"
    fi
    echo
}

function check_your_ip() {
    print_info "Checking external IP visibility..."
    
    echo -e "${YELLOW}Your real IP:${NC}"
    curl -s --connect-timeout 5 http://httpbin.org/ip 2>/dev/null || print_warn "Cannot check real IP"
    
    if ip netns list | grep -q vpn-client; then
        echo -e "${YELLOW}IP as seen through VPN:${NC}"
        ip netns exec vpn-client curl -s --connect-timeout 5 http://httpbin.org/ip 2>/dev/null || print_warn "Cannot check VPN IP"
    fi
    echo
}

function cleanup() {
    print_info "Cleaning up test environment..."
    
    # Remove network namespace
    ip netns del vpn-client 2>/dev/null || true
    
    # Remove veth pair
    ip link del veth-server 2>/dev/null || true
    
    # Clean iptables rules
    DEFAULT_IF=$(ip route show default | head -n1 | awk '{print $5}')
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_IF -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d 10.8.0.0/24 -j ACCEPT 2>/dev/null || true
    
    # Remove TUN interface
    ip link del tun-test 2>/dev/null || true
    
    print_info "Cleanup complete"
}

function run_full_test() {
    print_info "Running full VPN tunnel test..."
    echo
    
    setup_test_environment
    echo
    
    test_tun_interface
    echo
    
    simulate_client_traffic
    echo
    
    test_nat_functionality
    echo
    
    monitor_traffic
    echo
    
    test_packet_capture
    echo
    
    check_your_ip
    echo
    
    print_info "Full test completed. Press Enter to cleanup..."
    read
    cleanup
}

function show_usage() {
    echo "VPN Tunnel Test Script"
    echo "Usage: $0 [setup|test|cleanup|full]"
    echo
    echo "Commands:"
    echo "  setup   - Setup test environment only"
    echo "  test    - Run tests on existing setup"
    echo "  cleanup - Cleanup test environment"
    echo "  full    - Run full test (setup + test + cleanup)"
    echo "  help    - Show this help"
    echo
}

# Trap cleanup on exit
trap cleanup EXIT

# Main logic
case "${1:-full}" in
    "setup")
        check_root
        setup_test_environment
        ;;
    "test")
        check_root
        test_tun_interface
        test_nat_functionality
        monitor_traffic
        ;;
    "cleanup")
        check_root
        cleanup
        ;;
    "full")
        check_root
        run_full_test
        ;;
    "help"|*)
        show_usage
        ;;
esac