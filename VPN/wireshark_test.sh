#!/bin/bash
# wireshark_test.sh - Verify encryption with Wireshark

echo "=== Wireshark Encryption Verification ==="

# Install tshark if not available
if ! command -v tshark &> /dev/null; then
    echo "Installing tshark..."
    sudo apt-get install -y tshark
fi

# Capture packets
echo "Starting packet capture (20 seconds)..."
sudo tshark -i any -f "udp port 5502" -w /tmp/vpn_encrypted.pcap &
TSHARK_PID=$!

sleep 20
sudo kill $TSHARK_PID 2>/dev/null

# Analyze
echo ""
echo "Analyzing captured packets..."
echo ""

# Check packet count
PACKETS=$(tshark -r /tmp/vpn_encrypted.pcap 2>/dev/null | wc -l)
echo "Total packets: $PACKETS"

# Try to decode as various protocols (should all fail)
echo ""
echo "Protocol detection (should all show 'Data'):"
tshark -r /tmp/vpn_encrypted.pcap -Y "data" -T fields -e data 2>/dev/null | head -5

# Entropy check (encrypted data has high entropy)
echo ""
echo "Entropy check (high = encrypted):"
tshark -r /tmp/vpn_encrypted.pcap -T fields -e data 2>/dev/null | \
  head -100 | ent | grep "Entropy"

echo ""
echo "✓ If entropy > 7.9, data is well encrypted"

rm -f /tmp/vpn_encrypted.pcap