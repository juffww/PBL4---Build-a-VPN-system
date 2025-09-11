// tun_interface.cpp - Fixed implementation
#include "tun_interface.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/select.h>

TUNInterface::TUNInterface(const std::string& name) 
    : interfaceName(name), isOpen(false), tunFd(-1), bytesReceived(0), bytesSent(0)
{
}

TUNInterface::~TUNInterface() {
    close();
}

bool TUNInterface::create() {
    // Check if running as root
    if (getuid() != 0) {
        std::cerr << "[ERROR] TUN interface requires root privileges" << std::endl;
        return false;
    }

    // Check if /dev/net/tun exists
    if (access("/dev/net/tun", F_OK) != 0) {
        std::cerr << "[ERROR] /dev/net/tun does not exist. Please load tun module: modprobe tun" << std::endl;
        return false;
    }

    tunFd = open("/dev/net/tun", O_RDWR);
    if (tunFd < 0) {
        std::cerr << "[ERROR] Cannot open /dev/net/tun: " << strerror(errno) << std::endl;
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet info
    
    if (!interfaceName.empty()) {
        strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    }
    
    if (ioctl(tunFd, TUNSETIFF, (void*)&ifr) < 0) {
        std::cerr << "[ERROR] Cannot create TUN interface: " << strerror(errno) << std::endl;
        ::close(tunFd);
        tunFd = -1;
        return false;
    }
    
    interfaceName = ifr.ifr_name;
    isOpen = true;
    
    // Make the file descriptor non-blocking for better performance
    int flags = fcntl(tunFd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(tunFd, F_SETFL, flags | O_NONBLOCK);
    }
    
    std::cout << "[INFO] Created TUN interface: " << interfaceName << std::endl;
    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask, 
                             const std::string& server, bool isServerMode) {
    if (!isOpen) {
        std::cerr << "[ERROR] TUN interface not created" << std::endl;
        return false;
    }
    
    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;
    
    // Set IP address for interface
    if (!setIP(ip, mask)) {
        return false;
    }
    
    // Bring interface up
    std::string cmd = "ip link set dev " + interfaceName + " up";
    if (!executeCommand(cmd)) {
        std::cerr << "[ERROR] Cannot bring interface up" << std::endl;
        return false;
    }
    
    if (isServerMode) {
        // For server: Enable NAT and IP forwarding
        std::string defaultInterface = getDefaultInterface();
        if (defaultInterface.empty()) {
            std::cerr << "[WARN] Could not detect default interface, using eth0" << std::endl;
            defaultInterface = "eth0";
        }
        
        // Enable IP forwarding
        executeCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");
        
        // Add NAT rule for VPN clients
        cmd = "iptables -t nat -C POSTROUTING -s " + ip + "/" + mask + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || " +
              "iptables -t nat -A POSTROUTING -s " + ip + "/" + mask + " -o " + defaultInterface + " -j MASQUERADE";
        executeCommand(cmd);
        
        // Allow forwarding for VPN subnet
        cmd = "iptables -C FORWARD -s " + ip + "/" + mask + " -j ACCEPT 2>/dev/null || " +
              "iptables -A FORWARD -s " + ip + "/" + mask + " -j ACCEPT";
        executeCommand(cmd);
        
        cmd = "iptables -C FORWARD -d " + ip + "/" + mask + " -j ACCEPT 2>/dev/null || " +
              "iptables -A FORWARD -d " + ip + "/" + mask + " -j ACCEPT";
        executeCommand(cmd);
        
        std::cout << "[INFO] Server mode: NAT and forwarding enabled for " << defaultInterface << std::endl;
    } else {
        // For client: Set routes (implementation for client would go here)
        if (!setRoutes()) {
            std::cerr << "[WARN] Failed to set client routes" << std::endl;
        }
    }
    
    std::cout << "[INFO] Configured " << interfaceName << " with IP " << ip << "/" << mask << std::endl;
    return true;
}

bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
    std::string cmd = "ip addr add " + ip + "/" + mask + " dev " + interfaceName;
    if (!executeCommand(cmd)) {
        // Try to delete existing IP first, then add
        std::string delCmd = "ip addr del " + ip + "/" + mask + " dev " + interfaceName + " 2>/dev/null";
        executeCommand(delCmd);
        
        if (!executeCommand(cmd)) {
            std::cerr << "[ERROR] Cannot set IP address" << std::endl;
            return false;
        }
    }
    return true;
}

std::string TUNInterface::getDefaultInterface() {
    std::string interface;
    std::string cmd = "ip route show default | head -n1 | awk '{print $5}'";
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            interface = buffer;
            // Remove newline
            interface.erase(interface.find_last_not_of(" \n\r\t") + 1);
        }
        pclose(pipe);
    }
    
    return interface;
}

bool TUNInterface::setRoutes() {
    if (!isOpen) return false;
    
    // This is for client mode - backup and set routes
    executeCommand("ip route show default > /tmp/vpn_backup_route_" + interfaceName);
    
    // Add route to VPN server to avoid routing loop
    if (!serverIP.empty()) {
        std::string defaultGateway = getDefaultGateway();
        if (!defaultGateway.empty()) {
            std::string cmd = "ip route add " + serverIP + "/32 via " + defaultGateway + " 2>/dev/null";
            executeCommand(cmd);
        }
    }
    
    // Set default route through TUN (for full VPN)
    // This is commented out for server mode - clients would use this
    // std::string cmd = "ip route add 0.0.0.0/1 dev " + interfaceName;
    // executeCommand(cmd);
    // cmd = "ip route add 128.0.0.0/1 dev " + interfaceName;
    // executeCommand(cmd);
    
    std::cout << "[INFO] Client routes configured" << std::endl;
    return true;
}

std::string TUNInterface::getDefaultGateway() {
    std::string gateway;
    std::string cmd = "ip route show default | head -n1 | awk '{print $3}'";
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            gateway = buffer;
            // Remove newline
            gateway.erase(gateway.find_last_not_of(" \n\r\t") + 1);
        }
        pclose(pipe);
    }
    
    return gateway;
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    std::cout << "[CMD] " << cmd << std::endl;
    int result = system(cmd.c_str());
    bool success = (result == 0);
    if (!success) {
        std::cout << "[WARN] Command failed with exit code: " << result << std::endl;
    }
    return success;
}

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen || tunFd < 0) return -1;
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(tunFd, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 100ms timeout
    
    int ready = select(tunFd + 1, &readfds, nullptr, nullptr, &timeout);
    
    if (ready <= 0) return 0; // Timeout or error
    
    if (FD_ISSET(tunFd, &readfds)) {
        int bytes = read(tunFd, buffer, maxSize);
        if (bytes > 0) {
            bytesReceived += bytes;
        }
        return bytes;
    }
    
    return 0;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen || tunFd < 0) return -1;
    
    int bytes = write(tunFd, buffer, size);
    if (bytes > 0) {
        bytesSent += bytes;
    } else if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        std::cerr << "[ERROR] Write to TUN failed: " << strerror(errno) << std::endl;
    }
    return bytes;
}

void TUNInterface::close() {
    if (!isOpen) return;
    
    std::cout << "[INFO] Cleaning up TUN interface: " << interfaceName << std::endl;
    
    // Clean up routes and iptables rules
    if (!interfaceName.empty()) {
        // Remove IP address
        executeCommand("ip addr flush dev " + interfaceName + " 2>/dev/null");
        
        // Bring interface down
        executeCommand("ip link set dev " + interfaceName + " down 2>/dev/null");
        
        // Restore routes if backup exists
        std::string restoreCmd = "if [ -f /tmp/vpn_backup_route_" + interfaceName + " ]; then "
                                "GATEWAY=$(cat /tmp/vpn_backup_route_" + interfaceName + " | awk '{print $3}' | head -n1); "
                                "if [ ! -z \"$GATEWAY\" ]; then "
                                "ip route add default via $GATEWAY 2>/dev/null; "
                                "fi; "
                                "rm -f /tmp/vpn_backup_route_" + interfaceName + "; "
                                "fi";
        executeCommand(restoreCmd);
        
        // Clean NAT rules if this was server
        if (!vpnIP.empty() && !subnetMask.empty()) {
            std::string defaultInterface = getDefaultInterface();
            if (defaultInterface.empty()) defaultInterface = "eth0";
            
            executeCommand("iptables -t nat -D POSTROUTING -s " + vpnIP + "/" + subnetMask + 
                          " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null");
            executeCommand("iptables -D FORWARD -s " + vpnIP + "/" + subnetMask + " -j ACCEPT 2>/dev/null");
            executeCommand("iptables -D FORWARD -d " + vpnIP + "/" + subnetMask + " -j ACCEPT 2>/dev/null");
        }
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