#!/bin/bash

# Test script cho VPN tunnel
# Chạy script này sau khi client đã kết nối thành công

echo "=== VPN TUNNEL TEST SCRIPT ==="
echo "Kiểm tra kết nối VPN và routing..."

# Kiểm tra TUN interface
echo "1. Kiểm tra TUN interface..."
ip addr show | grep tun
echo

# Kiểm tra routing table
echo "2. Kiểm tra routing table..."
ip route show | grep -E "(tun|10\.8\.0)"
echo

# Test ping đến server VPN
echo "3. Test ping đến VPN server (10.8.0.1)..."
ping -c 3 10.8.0.1
echo

# Test ping đến client từ server (chạy trên server)
if [ "$1" == "server" ]; then
    echo "4. [SERVER] Test ping đến client (10.8.0.2)..."
    ping -c 3 10.8.0.2
    echo
fi

# Test ping DNS server qua VPN
echo "4. Test ping DNS server qua VPN..."
ping -c 3 8.8.8.8
echo

# Test HTTP request qua VPN
echo "5. Test HTTP request qua VPN..."
curl -m 10 http://httpbin.org/ip 2>/dev/null | head -5
echo

# Test traceroute để xem routing path
echo "6. Test traceroute đến 8.8.8.8..."
traceroute -n -m 5 8.8.8.8 | head -8
echo

# Kiểm tra iptables rules (chỉ trên server)
if [ "$1" == "server" ]; then
    echo "7. [SERVER] Kiểm tra iptables NAT rules..."
    iptables -t nat -L -n | grep -A 5 -B 5 "10.8.0"
    echo
    
    echo "8. [SERVER] Kiểm tra FORWARD rules..."
    iptables -L FORWARD -n | grep -A 5 -B 5 "10.8.0"
    echo
fi

echo "=== TEST HOÀN THÀNH ==="
echo
echo "Hướng dẫn debug:"
echo "- Nếu ping 10.8.0.1 FAIL: Kiểm tra TUN interface client"
echo "- Nếu ping 8.8.8.8 FAIL: Kiểm tra routing và NAT trên server"
echo "- Nếu HTTP request FAIL: Kiểm tra DNS resolution và NAT"
echo "- Xem log server và client để debug packet flow"