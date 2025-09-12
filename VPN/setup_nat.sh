#!/bin/bash
# Script cấu hình NAT + Forwarding cho VPN (tun0 -> wlo1)

echo "=== Cấu hình NAT + IP Forwarding cho VPN ==="

# Bật IP forwarding (cho phép Linux forward packet)
echo "1. Bật IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# Thêm rule NAT (MASQUERADE) để các gói từ VPN ra Internet qua wlo1
echo "2. Cấu hình iptables NAT..."
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o wlo1 -j MASQUERADE

# Cho phép forward gói tin giữa tun0 và wlo1
echo "3. Cấu hình iptables FORWARD rules..."
sudo iptables -A FORWARD -i tun0 -o wlo1 -j ACCEPT
sudo iptables -A FORWARD -i wlo1 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "✓ NAT + Forwarding đã bật thành công!"
