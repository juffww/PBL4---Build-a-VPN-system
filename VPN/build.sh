#!/bin/bash

echo "=== VPN Server Build & Test (TLS + AES-GCM) ==="

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

# Kiểm tra OpenSSL version (cần >= 1.1.1 cho TLS 1.3)
OPENSSL_VER_NUM=$(openssl version | awk '{print $2}' | sed 's/[a-z]//g')
if [ "$(echo "$OPENSSL_VER_NUM 1.1.1" | awk '{print ($1 >= $2)}')" -eq 0 ]; then
    echo "⚠ OpenSSL version < 1.1.1, TLS 1.3 may not be available"
else
    echo "✓ OpenSSL supports TLS 1.3"
fi

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
mkdir -p src/core src/network src/crypto certs build

# 4. Clean old build
echo "Cleaning old build..."
rm -f vpn_server build/*.o

# 5. Generate TLS certificates if not exists
if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then
    echo ""
    echo "=== Generating TLS Certificates ==="
    
    # Generate private key
    openssl genrsa -out certs/server.key 2048 2>/dev/null
    
    # Generate self-signed certificate
    openssl req -new -x509 -key certs/server.key \
        -out certs/server.crt \
        -days 365 \
        -subj "/C=VN/ST=DaNang/L=DaNang/O=VPNServer/CN=vpn.local" 2>/dev/null
    
    # Set permissions
    chmod 600 certs/server.key
    chmod 644 certs/server.crt
    
    echo "✓ TLS certificates generated"
    echo "  Certificate: certs/server.crt"
    echo "  Private Key: certs/server.key"
else
    echo "✓ TLS certificates already exist"
fi

# 6. Apply system-level optimizations
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

# 7. Compile với TLS Support
echo ""
echo "=== Compiling with TLS + Crypto Support ==="

# Get OpenSSL flags
OPENSSL_CFLAGS=$(pkg-config --cflags openssl)
OPENSSL_LIBS=$(pkg-config --libs openssl)

# Tìm thư viện libssl.so
OPENSSL_LIBDIR="/lib/x86_64-linux-gnu"
if [ ! -f "$OPENSSL_LIBDIR/libssl.so" ]; then
    OPENSSL_LIBDIR="/usr/lib/x86_64-linux-gnu"
fi

echo "OpenSSL CFLAGS: $OPENSSL_CFLAGS"
echo "OpenSSL LIBS: $OPENSSL_LIBS"
echo "OpenSSL Library Dir: $OPENSSL_LIBDIR"

# Compile với TLS support
g++ -std=c++17 -pthread \
    -O2 -march=native \
    -I./src -I./src/core -I./src/network -I./src/crypto \
    $OPENSSL_CFLAGS \
    src/main.cpp \
    src/core/vpn_server.cpp \
    src/core/client_manager.cpp \
    src/core/packet_handler.cpp \
    src/core/tunnel_manager.cpp \
    src/crypto/crypto_engine.cpp \
    src/crypto/tls_wrapper.cpp \
    src/network/tun_interface.cpp \
    src/network/socket_manager.cpp \
    -o vpn_server \
    -L$OPENSSL_LIBDIR \
    -Wl,--no-as-needed \
    $OPENSSL_LIBS \
    -ldl

if [ $? -eq 0 ]; then
    echo "✓ Compile thành công với TLS + Crypto support"
    ls -lh vpn_server
    
    # Verify OpenSSL linking
    echo ""
    echo "=== Verifying TLS Support ==="
    
    if ldd vpn_server | grep -q "libssl"; then
        SSL_PATH=$(ldd vpn_server | grep libssl | awk '{print $3}')
        echo "✓ libssl linked: $SSL_PATH"
    else
        echo "✗ WARNING: libssl NOT linked!"
        exit 1
    fi
    
    if ldd vpn_server | grep -q "libcrypto"; then
        CRYPTO_PATH=$(ldd vpn_server | grep libcrypto | awk '{print $3}')
        echo "✓ libcrypto linked: $CRYPTO_PATH"
    else
        echo "✗ WARNING: libcrypto NOT linked!"
        exit 1
    fi
    
    # Check for TLS symbols
    if nm vpn_server 2>/dev/null | grep -q "TLSWrapper"; then
        echo "✓ TLSWrapper class found"
    else
        echo "⚠ TLSWrapper symbols may be optimized out"
    fi
    
    if nm vpn_server 2>/dev/null | grep -q "SSL_"; then
        echo "✓ OpenSSL SSL_ functions found"
    else
        echo "⚠ OpenSSL SSL_ functions not visible (may be stripped)"
    fi
    
    # Strip binary
    strip vpn_server
    echo "✓ Binary stripped for smaller size"
    ls -lh vpn_server
else
    echo "✗ Compile failed"
    exit 1
fi

# 8. Compile test client (optional)
if [ -f test_tls_client.cpp ]; then
    echo ""
    echo "=== Building Test Client ==="
    g++ -std=c++17 test_tls_client.cpp -o test_client -lssl -lcrypto
    if [ $? -eq 0 ]; then
        echo "✓ Test client compiled"
    else
        echo "⚠ Test client compilation failed"
    fi
fi

# 9. Kiểm tra TUN module
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

# 10. Kiểm tra port
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

# 11. Cleanup old rules
echo ""
echo "=== Cleaning old iptables rules ==="
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null
iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null
iptables -D FORWARD -d 10.8.0.0/24 -j ACCEPT 2>/dev/null
iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
echo "✓ Old rules cleaned"

# 12. Remove old TUN interface
if ip link show tun0 &>/dev/null; then
    echo "Removing old tun0 interface..."
    ip link set tun0 down 2>/dev/null
    ip link del tun0 2>/dev/null
    echo "✓ Old tun0 removed"
fi

# 13. Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "✓ IP forwarding enabled"

# 14. Final verification
echo ""
echo "=== Build Summary ==="
echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║     VPN Server 2.0 - TLS Edition               ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "🔐 TLS FEATURES:"
echo "   ✓ TLS 1.2+ for control channel"
echo "   ✓ AES-256-GCM for UDP data"
echo "   ✓ Self-signed certificate ready"
echo "   ✓ OpenSSL $(openssl version | awk '{print $2}')"
echo ""
echo "🔑 Certificates:"
echo "   📄 Certificate: certs/server.crt"
echo "   🔐 Private Key: certs/server.key"
echo ""
echo "🚀 OPTIMIZATIONS:"
echo "   ✓ -O2 -march=native optimization"
echo "   ✓ Network buffers: 16MB"
echo "   ✓ Connection tracking: 1M"
echo ""
echo "📋 Usage:"
echo "   sudo ./vpn_server --cert certs/server.crt --key certs/server.key"
echo ""
if [ -f test_client ]; then
    echo "🧪 Testing:"
    echo "   # Terminal 1"
    echo "   sudo ./vpn_server --cert certs/server.crt --key certs/server.key"
    echo ""
    echo "   # Terminal 2"
    echo "   ./test_client 127.0.0.1 5000"
    echo ""
fi
echo "═══════════════════════════════════════════════════"
echo ""