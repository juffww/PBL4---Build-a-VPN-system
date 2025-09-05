// tun_interface.cpp - Linux implementation
#include "tun_interface.h"
#include <iostream>
#include <cstring>
#include <sstream>

TUNInterface::TUNInterface(const std::string& name) 
    : interfaceName(name), isOpen(false), tunFd(-1), bytesReceived(0), bytesSent(0)
{
}

TUNInterface::~TUNInterface() {
    close();
}

bool TUNInterface::create() {
    // Mở /dev/net/tun
    tunFd = open("/dev/net/tun", O_RDWR);
    if (tunFd < 0) {
        std::cerr << "[ERROR] Cannot open /dev/net/tun - requires root privileges" << std::endl;
        return false;
    }
    
    // Cấu hình TUN interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet info
    
    // Set interface name
    if (!interfaceName.empty()) {
        strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    }
    
    // Tạo TUN interface
    if (ioctl(tunFd, TUNSETIFF, (void*)&ifr) < 0) {
        std::cerr << "[ERROR] Cannot create TUN interface: " << strerror(errno) << std::endl;
        ::close(tunFd);
        tunFd = -1;
        return false;
    }
    
    // Lưu tên interface thực tế
    interfaceName = ifr.ifr_name;
    isOpen = true;
    
    std::cout << "[INFO] Created TUN interface: " << interfaceName << std::endl;
    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask, 
                           const std::string& server) {
    if (!isOpen) {
        std::cerr << "[ERROR] TUN interface not created" << std::endl;
        return false;
    }
    
    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;
    
    // Set IP address cho interface
    if (!setIP(ip, mask)) {
        return false;
    }
    
    // Bring interface up
    std::string cmd = "ip link set dev " + interfaceName + " up";
    if (!executeCommand(cmd)) {
        std::cerr << "[ERROR] Cannot bring interface up" << std::endl;
        return false;
    }
    
    std::cout << "[INFO] Configured " << interfaceName << " with IP " << ip << std::endl;
    return true;
}

bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
    // Add IP address to interface
    std::string cmd = "ip addr add " + ip + "/24 dev " + interfaceName;
    if (!executeCommand(cmd)) {
        std::cerr << "[ERROR] Cannot set IP address" << std::endl;
        return false;
    }
    return true;
}

bool TUNInterface::setRoutes() {
    if (!isOpen) return false;
    
    // Backup default route
    executeCommand("ip route show default > /tmp/vpn_backup_route");
    
    // Add route to VPN server (để tránh routing loop)
    if (!serverIP.empty()) {
        std::string cmd = "ip route add " + serverIP + "/32 via $(ip route | grep default | awk '{print $3}' | head -n1)";
        executeCommand(cmd);
    }
    
    // Set default route through VPN
    std::string cmd = "ip route del default";
    executeCommand(cmd); // Ignore errors
    
    cmd = "ip route add default dev " + interfaceName;
    if (!executeCommand(cmd)) {
        std::cerr << "[ERROR] Cannot set default route" << std::endl;
        return false;
    }
    
    // Set DNS
    executeCommand("echo 'nameserver 8.8.8.8' > /tmp/vpn_resolv.conf");
    executeCommand("cp /etc/resolv.conf /tmp/vpn_backup_resolv.conf");
    executeCommand("cp /tmp/vpn_resolv.conf /etc/resolv.conf");
    
    std::cout << "[INFO] VPN routes configured" << std::endl;
    return true;
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    std::cout << "[CMD] " << cmd << std::endl;
    int result = system(cmd.c_str());
    return result == 0;
}

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen || tunFd < 0) return -1;
    
    int bytes = read(tunFd, buffer, maxSize);
    if (bytes > 0) {
        bytesReceived += bytes;
    }
    return bytes;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen || tunFd < 0) return -1;
    
    int bytes = write(tunFd, buffer, size);
    if (bytes > 0) {
        bytesSent += bytes;
    }
    return bytes;
}

void TUNInterface::close() {
    if (!isOpen) return;
    
    // Restore routes
    if (!interfaceName.empty()) {
        executeCommand("ip route del default dev " + interfaceName);
        executeCommand("ip route add default via $(cat /tmp/vpn_backup_route | awk '{print $3}')");
        executeCommand("cp /tmp/vpn_backup_resolv.conf /etc/resolv.conf");
    }
    
    if (tunFd >= 0) {
        ::close(tunFd);
        tunFd = -1;
    }
    
    isOpen = false;
    std::cout << "[INFO] TUN interface closed" << std::endl;
}

void TUNInterface::resetStats() {
    bytesReceived = 0;
    bytesSent = 0;
}