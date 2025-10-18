#!/bin/bash

echo "=== VPN Server Build & Test ==="

# 1. Kiểm tra quyền root TRƯỚC KHI compile
if [ "$EUID" -ne 0 ]; then
    echo "⚠ Cần chạy với quyền root để build và test"
    echo "Sử dụng: sudo ./build.sh"
    exit 1
fi

# 2. Tạo thư mục structure
echo "Creating directory structure..."
mkdir -p src/core src/network build

# 3. Clean old build
echo "Cleaning old build..."
rm -f vpn_server build/*.o

# 4. Compile với optimization flags
echo "Compiling..."

g++ -std=c++17 -pthread -O2 -Wall -Wextra \
    -o vpn_server \
    src/main.cpp \
    src/core/vpn_server.cpp \
    src/core/client_manager.cpp \
    src/core/packet_handler.cpp \
    src/core/tunnel_manager.cpp \
    src/network/tun_interface.cpp \
    src/network/socket_manager.cpp \
    -I./src

if [ $? -eq 0 ]; then
    echo "✓ Compile thành công"
    ls -lh vpn_server
else
    echo "✗ Compile failed"
    exit 1
fi

# 5. Kiểm tra TUN module
echo ""
echo "=== Checking System Requirements ==="

if ! lsmod | grep -q tun; then
    echo "Loading TUN module..."
    modprobe tun
    if [ $? -eq 0 ]; then
        echo "✓ TUN module loaded"
    else
        echo "✗ Failed to load TUN module"
        exit 1
    fi
else
    echo "✓ TUN module already loaded"
fi

if [ -c /dev/net/tun ]; then
    echo "✓ /dev/net/tun exists"
else
    echo "✗ /dev/net/tun not found"
    exit 1
fi

# 6. Kiểm tra port có bị chiếm không
if ss -tuln | grep -q ":1194 "; then
    echo "⚠ Port 1194 đã được sử dụng"
    echo "Killing existing process..."
    fuser -k 1194/tcp 2>/dev/null
    sleep 1
fi

if ss -tuln | grep -q ":5502 "; then
    echo "⚠ Port 5502 (UDP) đã được sử dụng"
    echo "Killing existing process..."
    fuser -k 5502/udp 2>/dev/null
    sleep 1
fi

# 7. Kiểm tra iptables rules cũ
echo ""
echo "=== Cleaning old iptables rules ==="
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null
iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null
iptables -D FORWARD -d 10.8.0.0/24 -j ACCEPT 2>/dev/null
echo "✓ Old rules cleaned"

# 8. Xóa TUN interface cũ nếu có
if ip link show tun0 &>/dev/null; then
    echo "Removing old tun0 interface..."
    ip link set tun0 down 2>/dev/null
    ip link del tun0 2>/dev/null
fi

# 9. Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "✓ IP forwarding enabled"

echo ""
echo "=== Build Completed Successfully ==="
echo ""
echo "📋 To run the server:"
echo "   sudo ./vpn_server"
echo ""
echo "📋 Basic commands:"
echo "   start       - Start the VPN server"
echo "   status      - Check server status"
echo "   clients     - List connected clients"
echo "   help        - Show all commands"
echo "   quit        - Exit"
echo ""
echo "🔧 Useful system commands:"
echo "   ip addr show tun0              - Check TUN interface"
echo "   ip route | grep tun0           - Check routing"
echo "   iptables -t nat -L -n -v       - Check NAT rules"
echo "   ss -tuln | grep -E '1194|5502' - Check listening ports"
echo ""
echo "⚠️  Remember: Server needs root privileges!"