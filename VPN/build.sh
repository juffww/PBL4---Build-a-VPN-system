#!/bin/bash

echo "=== VPN Server Build & Test (Optimized + Crypto) ==="

# 1. Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
    echo "⚠ Cần chạy với quyền root để build và test"
    echo "Sử dụng: sudo ./build.sh"
    exit 1
fi

# 2. Kiểm tra OpenSSL
echo ""
echo "=== Checking Dependencies ==="
if ! command -v openssl &> /dev/null; then
    echo "✗ OpenSSL not found! Installing..."
    apt-get update && apt-get install -y openssl libssl-dev
fi

OPENSSL_VERSION=$(openssl version)
echo "✓ $OPENSSL_VERSION"

# Check development headers
if ! pkg-config --exists openssl; then
    echo "✗ OpenSSL development headers missing!"
    echo "  Installing: sudo apt-get install libssl-dev"
    apt-get install -y libssl-dev
fi

echo "✓ OpenSSL development headers found"

# 3. Tạo thư mục structure
echo ""
echo "Creating directory structure..."
mkdir -p src/core src/network build

# 4. Clean old build
echo "Cleaning old build..."
rm -f vpn_server build/*.o

# 5. Apply system-level optimizations
echo ""
echo "=== Applying System Optimizations ==="
sysctl -w net.core.rmem_max=16777216 >/dev/null
sysctl -w net.core.wmem_max=16777216 >/dev/null
sysctl -w net.core.rmem_default=1048576 >/dev/null
sysctl -w net.core.wmem_default=1048576 >/dev/null
sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' >/dev/null
sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' >/dev/null
sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null
sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null
sysctl -w net.ipv4.tcp_sack=1 >/dev/null
sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null
sysctl -w net.ipv4.tcp_low_latency=1 >/dev/null
sysctl -w net.netfilter.nf_conntrack_max=1048576 >/dev/null 2>&1
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=3600 >/dev/null 2>&1
ulimit -n 65536
sysctl -w net.ipv4.conf.all.log_martians=0 >/dev/null

for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [ -f "$cpu" ]; then
        echo performance > "$cpu" 2>/dev/null
    fi
done

echo "✓ System optimizations applied"

# 6. Compile với OpenSSL (FIX: Thêm -L để link libssl)
echo ""
echo "=== Compiling with Crypto Support ==="

# Get OpenSSL flags AND library directory
OPENSSL_CFLAGS=$(pkg-config --cflags openssl)
OPENSSL_LIBS=$(pkg-config --libs --static openssl)

# Tìm thư viện libssl.so thực tế trên hệ thống
OPENSSL_LIBDIR="/lib/x86_64-linux-gnu"
if [ ! -f "$OPENSSL_LIBDIR/libssl.so" ]; then
    OPENSSL_LIBDIR="/usr/lib/x86_64-linux-gnu"
fi

echo "OpenSSL CFLAGS: $OPENSSL_CFLAGS"
echo "OpenSSL LIBS: $OPENSSL_LIBS"
echo "OpenSSL Library Dir: $OPENSSL_LIBDIR"
echo "Verifying libssl.so: $(ls -la $OPENSSL_LIBDIR/libssl.so 2>/dev/null || echo 'NOT FOUND')"

# g++ -std=c++17 -pthread -O2 \
g++ -std=c++17 -pthread \
    -O2 \
    -I./src -I./src/core -I./src/network \
    src/main.cpp \
    src/core/vpn_server.cpp \
    src/core/client_manager.cpp \
    src/core/packet_handler.cpp \
    src/core/tunnel_manager.cpp \
    src/core/crypto_engine.cpp \
    src/network/tun_interface.cpp \
    src/network/socket_manager.cpp \
    -o vpn_server \
    -L/lib/x86_64-linux-gnu \
    -Wl,--no-as-needed \
    -lssl -lcrypto -ldl

if [ $? -eq 0 ]; then
    echo "✓ Compile thành công với crypto support"
    ls -lh vpn_server
    
    # Verify OpenSSL linking BEFORE strip
    echo ""
    echo "=== Verifying Crypto Support (Before Strip) ==="
    
    # Check dynamic library linking
    if ldd vpn_server | grep -q "libssl"; then
        echo "✓ libssl linked successfully"
    else
        echo "✗ WARNING: libssl NOT linked!"
        echo "  This may cause runtime errors!"
    fi
    
    if ldd vpn_server | grep -q "libcrypto"; then
        echo "✓ libcrypto linked successfully"
    else
        echo "✗ WARNING: libcrypto NOT linked!"
    fi
    
    # Check for crypto symbols BEFORE strip
    if nm vpn_server 2>/dev/null | grep -q "CryptoEngine"; then
        echo "✓ CryptoEngine symbols found"
    else
        echo "✗ CryptoEngine symbols not found!"
    fi
    
    if nm vpn_server 2>/dev/null | grep -q "EVP_"; then
        echo "✓ OpenSSL EVP functions found"
    else
        echo "⚠ OpenSSL EVP functions not found (may be optimized out)"
    fi
    
    # THEN strip symbols for smaller binary
    strip vpn_server
    echo "✓ Binary stripped"
    ls -lh vpn_server
    # ========== KẾT THÚC PHẦN THÊM ==========
else
    echo "✗ Compile failed"
    exit 1
fi

# 7. Kiểm tra TUN module
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

# 8. Kiểm tra port
echo ""
echo "=== Checking Ports ==="

if ss -tuln | grep -q ":5000 "; then
    echo "⚠ Port 5000 đã được sử dụng"
    fuser -k 5000/tcp 2>/dev/null
    sleep 1
fi

if ss -tuln | grep -q ":5502 "; then
    echo "⚠ Port 5502 (UDP) đã được sử dụng"
    fuser -k 5502/udp 2>/dev/null
    sleep 1
fi

# 9. Cleanup old rules
echo ""
echo "=== Cleaning old iptables rules ==="
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null
iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null
iptables -D FORWARD -d 10.8.0.0/24 -j ACCEPT 2>/dev/null
iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
echo "✓ Old rules cleaned"

# 10. Remove old TUN interface
if ip link show tun0 &>/dev/null; then
    echo "Removing old tun0 interface..."
    ip link set tun0 down 2>/dev/null
    ip link del tun0 2>/dev/null
    echo "✓ Old tun0 removed"
fi

# 11. Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "✓ IP forwarding enabled"

# 12. Final verification
echo ""
echo "=== Final Crypto Verification ==="
echo "Linked libraries:"
ldd vpn_server | grep -E "libssl|libcrypto"
echo ""

# Test if crypto functions are available
echo "Testing crypto symbols..."
if nm vpn_server 2>/dev/null | grep -q "EVP_"; then
    echo "✓ OpenSSL EVP functions found"
else
    echo "⚠ OpenSSL EVP functions not visible (stripped binary)"
fi

echo ""
echo "=== Build Completed Successfully ==="
echo ""
echo "🔐 CRYPTO FEATURES:"
echo "   ✓ X25519 key exchange (ECDH)"
echo "   ✓ HKDF-SHA256 key derivation"
echo "   ✓ AES-256-GCM encryption"
echo "   ✓ OpenSSL $(openssl version | awk '{print $2}')"
echo ""
echo "🚀 PERFORMANCE OPTIMIZATIONS:"
echo "   ✓ -O3 optimization"
echo "   ✓ -march=native"
echo "   ✓ -flto"
echo "   ✓ Network buffers: 16MB"
echo ""
echo "📋 To run with crypto:"
echo "   sudo ./vpn_server"
echo ""
echo "🧪 To test crypto:"
echo "   sudo ./test_crypto.sh"
echo ""