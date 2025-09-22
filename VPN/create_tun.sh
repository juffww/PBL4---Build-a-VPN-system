#!/bin/bash
set -e

# Tạo interface tun0
sudo ip tuntap add dev tun0 mode tun user $(whoami)

# Bật interface
sudo ip link set tun0 up

# Gán IP cho tun0 (IP máy host)
sudo ip addr add 10.8.0.1/24 dev tun0

# Xoá route link-local mặc định để tránh gói rác (169.254.0.0/16)
sudo ip route del 169.254.0.0/16 dev tun0 2>/dev/null || true

# Chỉ cho phép route nội bộ 10.8.0.0/24
sudo ip route replace 10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.1

echo "[OK] TUN interface tun0 đã được tạo với IP 10.8.0.1/24"
ip addr show dev tun0
ip route show dev tun0
