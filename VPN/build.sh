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

if ss -tuln | grep -q ":51820 "; then
    echo "⚠ Port 51820 (UDP) đã được sử dụng"
    echo "Killing existing process..."
    fuser -k 51820/udp 2>/dev/null
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

# 10. Test run (optional - comment out nếu không muốn auto-test)
echo ""
echo "=== Quick Test (10 seconds) ==="
echo "Starting server..."

# Chạy server trong background với timeout
timeout 10s ./vpn_server > test_output.log 2>&1 &
SERVER_PID=$!
sleep 3

# Kiểm tra server có chạy không
if ps -p $SERVER_PID > /dev/null; then
    echo "✓ Server process running (PID: $SERVER_PID)"
    
    # Kiểm tra TCP port
    if ss -tuln | grep -q ":1194 "; then
        echo "✓ TCP port 1194 listening"
    else
        echo "✗ TCP port 1194 NOT listening"
    fi
    
    # Kiểm tra UDP port
    if ss -tuln | grep -q ":51820 "; then
        echo "✓ UDP port 51820 listening"
    else
        echo "✗ UDP port 51820 NOT listening"
    fi
    
    # Kiểm tra TUN interface
    sleep 1
    if ip link show | grep -q "tun0"; then
        echo "✓ TUN interface created:"
        ip addr show tun0 | grep -E "inet |UP"
    else
        echo "⚠ TUN interface not yet created (waiting for first client)"
    fi
    
    # Hiển thị 10 dòng log cuối
    echo ""
    echo "=== Server Log (last 10 lines) ==="
    tail -10 test_output.log
    
else
    echo "✗ Server failed to start"
    echo ""
    echo "=== Error Log ==="
    cat test_output.log
    exit 1
fi

# Cleanup test
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "=== Build & Test Completed ==="
echo ""
echo "📋 Next steps:"
echo "   1. Run server:     sudo ./vpn_server"
echo "   2. In VPN prompt:  start"
echo "   3. Check status:   status"
echo "   4. View logs:      tail -f /tmp/vpn_server.log (if logging enabled)"
echo ""
echo "🔧 Useful commands:"
echo "   - Check TUN:       ip addr show tun0"
echo "   - Check routes:    ip route | grep tun0"
echo "   - Check NAT:       iptables -t nat -L -n -v"
echo "   - Check traffic:   watch -n1 'ss -tuln | grep -E \"1194|51820\"'"
echo ""
echo "⚠️  Remember: Server needs root privileges!"