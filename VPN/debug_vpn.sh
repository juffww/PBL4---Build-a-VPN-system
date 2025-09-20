#!/bin/bash

# VPN Debug và Monitoring Script
# Usage: ./debug_vpn.sh [server|client|test|monitor]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

function print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root for full functionality"
        echo "Try: sudo $0 $@"
        exit 1
    fi
}

function check_tun_module() {
    print_header "Checking TUN/TAP Module"
    
    if lsmod | grep -q tun; then
        print_info "TUN module is loaded"
    else
        print_warn "TUN module not loaded, attempting to load..."
        modprobe tun
        if [ $? -eq 0 ]; then
            print_info "TUN module loaded successfully"
        else
            print_error "Failed to load TUN module"
        fi
    fi
    
    if [ -e /dev/net/tun ]; then
        print_info "/dev/net/tun exists"
        ls -la /dev/net/tun
    else
        print_error "/dev/net/tun does not exist"
    fi
    echo
}

function show_network_interfaces() {
    print_header "Network Interfaces"
    ip addr show | grep -E "(inet|UP|DOWN|tun|tap)"
    echo
}

function show_routing_table() {
    print_header "Routing Table"
    ip route show
    echo
    
    print_header "Default Route"
    ip route show default
    echo
}

function show_iptables_rules() {
    print_header "IPTables Rules"
    
    echo -e "${YELLOW}NAT Rules:${NC}"
    iptables -t nat -L -n -v | grep -E "(MASQUERADE|10.8.0)"
    echo
    
    echo -e "${YELLOW}Filter Rules:${NC}"
    iptables -L FORWARD -n -v | grep -E "(10.8.0|tun)"
    echo
}

function monitor_tun_traffic() {
    print_header "Monitoring TUN Traffic"
    
    TUN_INTERFACE="tun0"
    
    if ip link show $TUN_INTERFACE >/dev/null 2>&1; then
        print_info "Monitoring traffic on $TUN_INTERFACE (Press Ctrl+C to stop)"
        echo -e "${YELLOW}RX/TX Stats:${NC}"
        
        while true; do
            RX_BYTES=$(cat /sys/class/net/$TUN_INTERFACE/statistics/rx_bytes 2>/dev/null || echo "0")
            TX_BYTES=$(cat /sys/class/net/$TUN_INTERFACE/statistics/tx_bytes 2>/dev/null || echo "0")
            RX_PACKETS=$(cat /sys/class/net/$TUN_INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
            TX_PACKETS=$(cat /sys/class/net/$TUN_INTERFACE/statistics/tx_packets 2>/dev/null || echo "0")
            
            printf "\r${GREEN}RX:${NC} %10s bytes (%s packets) ${GREEN}TX:${NC} %10s bytes (%s packets)" \
                   "$RX_BYTES" "$RX_PACKETS" "$TX_BYTES" "$TX_PACKETS"
            sleep 1
        done
    else
        print_error "TUN interface $TUN_INTERFACE not found"
    fi
}

function test_connectivity() {
    print_header "Testing VPN Connectivity"
    
    # Test server VPN IP
    print_info "Testing server VPN IP (10.8.0.1)..."
    ping -c 3 10.8.0.1
    echo
    
    # Test client VPN IPs
    print_info "Testing client VPN IPs..."
    for i in {2..5}; do
        echo -n "Testing 10.8.0.$i: "
        if ping -c 1 -W 1 10.8.0.$i >/dev/null 2>&1; then
            echo -e "${GREEN}ALIVE${NC}"
        else
            echo -e "${RED}NO RESPONSE${NC}"
        fi
    done
    echo
    
    # Test internet through VPN
    print_info "Testing internet connectivity through VPN..."
    echo "Checking DNS resolution:"
    nslookup google.com
    echo
    
    echo "Checking HTTP connectivity:"
    curl -s --connect-timeout 5 http://httpbin.org/ip | head -5
    echo
}

function show_vpn_processes() {
    print_header "VPN Related Processes"
    ps aux | grep -E "(vpn|tun)" | grep -v grep
    echo
    
    print_header "Network Connections"
    netstat -tlnp | grep -E "(1194|8080)"
    echo
}

function analyze_packet_flow() {
    print_header "Packet Flow Analysis"
    
    # Check if tcpdump is available
    if ! command -v tcpdump &> /dev/null; then
        print_warn "tcpdump not found. Installing..."
        apt-get update && apt-get install -y tcpdump
    fi
    
    print_info "Analyzing packet flow on tun0 (5 seconds)..."
    timeout 5 tcpdump -i tun0 -c 10 -n 2>/dev/null || print_warn "No packets captured on tun0"
    echo
}

function show_system_info() {
    print_header "System Information"
    
    echo -e "${YELLOW}Kernel Version:${NC}"
    uname -r
    echo
    
    echo -e "${YELLOW}IP Forward Status:${NC}"
    cat /proc/sys/net/ipv4/ip_forward
    echo
    
    echo -e "${YELLOW}Available Memory:${NC}"
    free -h
    echo
    
    echo -e "${YELLOW}Network Namespaces:${NC}"
    ip netns list 2>/dev/null || echo "None"
    echo
}

function debug_server() {
    print_header "VPN Server Debug Information"
    
    check_tun_module
    show_system_info
    show_network_interfaces
    show_routing_table
    show_iptables_rules
    show_vpn_processes
    
    print_info "To monitor traffic in real-time, run: $0 monitor"
}

function debug_client() {
    print_header "VPN Client Debug Information"
    
    show_network_interfaces
    show_routing_table
    test_connectivity
    
    print_info "Client debugging complete"
}

function run_tests() {
    print_header "Running VPN Tests"
    
    check_tun_module
    test_connectivity
    analyze_packet_flow
    
    print_info "All tests completed"
}

function show_usage() {
    echo "Usage: $0 [server|client|test|monitor]"
    echo
    echo "Commands:"
    echo "  server  - Debug VPN server configuration"
    echo "  client  - Debug VPN client configuration"  
    echo "  test    - Run connectivity tests"
    echo "  monitor - Monitor TUN interface traffic"
    echo "  help    - Show this help message"
    echo
    echo "Examples:"
    echo "  sudo $0 server    # Debug server setup"
    echo "  sudo $0 test      # Test VPN connectivity"
    echo "  sudo $0 monitor   # Monitor traffic"
}

# Main script logic
case "${1:-help}" in
    "server")
        check_permissions
        debug_server
        ;;
    "client")
        debug_client
        ;;
    "test")
        check_permissions
        run_tests
        ;;
    "monitor")
        check_permissions
        monitor_tun_traffic
        ;;
    "help"|*)
        show_usage
        ;;
esac