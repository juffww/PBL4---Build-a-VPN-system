#!/bin/bash

echo "=== VPN Server Build & Test ==="

# 1. Tạo thư mục structure
mkdir -p src/core src/network

# 2. Compile
echo "Compiling..."
# g++ -std=c++11 -pthread -o vpn_server \
#     src/main.cpp \
#     src/core/vpn_server.cpp \
#     src/network/tun_interface.cpp \
#     src/network/socket_manager.cpp \
#     src/core/client_manager.cpp\
#     -I./src
g++ -std=c++11 -pthread -o vpn_server \
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
else
    echo "✗ Compile failed"
    exit 1
fi

# 3. Kiểm tra permissions
if [ "$EUID" -ne 0 ]; then
    echo "⚠ Cần chạy với quyền root để tạo TUN interface"
    echo "Sử dụng: sudo ./build.sh"
    exit 1
fi

echo "✓ Running as root"

# 4. Kiểm tra TUN module
if ! lsmod | grep -q tun; then
    echo "Loading TUN module..."
    modprobe tun
fi

if [ -c /dev/net/tun ]; then
    echo "✓ /dev/net/tun exists"
else
    echo "✗ /dev/net/tun not found"
    exit 1
fi

# 5. Test basic functionality
echo ""
echo "=== Testing TUN Interface ==="
./vpn_server &
SERVER_PID=$!
sleep 2

echo "start 1194" | netcat localhost 1194 &
sleep 1

# Kiểm tra TUN interface được tạo
if ip link show | grep -q tun; then
    echo "✓ TUN interface created"
    ip link show | grep tun
else
    echo "? No TUN interface found (normal for TCP-only mode)"
fi

# Kiểm tra server listening
if netstat -ln | grep -q ":1194"; then
    echo "✓ Server listening on port 1194"
else
    echo "✗ Server not listening"
fi

# Cleanup
kill $SERVER_PID 2>/dev/null
echo ""
echo "=== Test completed ==="
echo "Run manually: sudo ./vpn_server"
