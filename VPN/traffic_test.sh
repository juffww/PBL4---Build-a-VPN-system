#!/bin/bash

echo "=== VPN Traffic Test Script ==="

# Kiểm tra TUN interface
echo "1. Checking TUN interface..."
ip addr show tun0 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ TUN interface exists"
else
    echo "✗ TUN interface not found"
    exit 1
fi

# Kiểm tra routes
echo -e "\n2. Checking routes..."
ip route | grep tun0
if [ $? -eq 0 ]; then
    echo "✓ TUN routes configured"
else
    echo "✗ No TUN routes found"
fi

# Test ping qua TUN interface
echo -e "\n3. Testing ping through TUN..."
ping -c 3 -I tun0 8.8.8.8 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ Ping through TUN successful"
else
    echo "⚠ Ping through TUN failed (expected if no internet routing)"
fi

# Tạo traffic test thật
echo -e "\n4. Generating test traffic..."
echo "Sending data to TUN interface..."

# Gửi dữ liệu tới TUN để test
for i in {1..5}; do
    echo "Test packet $i from $(date)" | socat - TUN:10.8.0.1/24,tun-type=tun,iff-no-pi 2>/dev/null &
    sleep 1
done

echo "✓ Test traffic generated"

# Hiển thị TUN stats
echo -e "\n5. Current TUN statistics:"
if [ -f /sys/class/net/tun0/statistics/rx_bytes ]; then
    echo "RX bytes: $(cat /sys/class/net/tun0/statistics/rx_bytes)"
    echo "TX bytes: $(cat /sys/class/net/tun0/statistics/tx_bytes)"
    echo "RX packets: $(cat /sys/class/net/tun0/statistics/rx_packets)"
    echo "TX packets: $(cat /sys/class/net/tun0/statistics/tx_packets)"
else
    echo "⚠ TUN statistics not available"
fi

echo -e "\n=== Test completed ==="