#include "tunnel_manager.h"
#include "packet_handler.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <thread>
#include <chrono>
#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <sys/socket.h>
    #include <errno.h>
#endif

TunnelManager::TunnelManager(const std::string& interfaceName)
    : tunInterface(nullptr), tunnelThreadRunning(false), 
      packetHandler(nullptr), interfaceName(interfaceName) {
}

TunnelManager::~TunnelManager() {
    stop();
    if (tunInterface) {
        delete tunInterface;
        tunInterface = nullptr;
    }
}

bool TunnelManager::initialize(const std::string& serverIP, const std::string& subnet, PacketHandler* handler) {
    std::cout << "[TUNNEL] Initializing tunnel manager...\n";
    
    packetHandler = handler;
    
    // Tạo TUN interface
    tunInterface = new TUNInterface(interfaceName);
    if (!tunInterface->create()) {
        std::cout << "[ERROR] Cannot create TUN interface\n";
        return false;
    }
    
    // Cấu hình TUN interface với server mode
    if (!tunInterface->configure(serverIP, "24", "", true)) {
        std::cout << "[ERROR] Cannot configure TUN interface\n";
        return false;
    }
    
    // Thiết lập routing cho VPN subnet
    setupVPNRouting(serverIP, subnet);
    
    std::cout << "[TUNNEL] TUN interface ready: "
              << tunInterface->getName() << " ("
              << tunInterface->getIP() << "/" << tunInterface->getMask() << ")\n";
    
    return true;
}

void TunnelManager::setupVPNRouting(const std::string& serverIP, const std::string& subnet) {
    std::cout << "[TUNNEL] Setting up VPN routing...\n";
    
    // Thêm route cho VPN subnet
    std::string routeCmd = "ip route add " + subnet + "/24 dev " + tunInterface->getName() + " 2>/dev/null || true";
    tunInterface->executeCommand(routeCmd);
    
    // Cấu hình NAT và forwarding
    setupNATRules(subnet);
    
    std::cout << "[TUNNEL] VPN routing configured\n";
}

void TunnelManager::setupNATRules(const std::string& subnet) {
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) {
        std::cout << "[WARN] Could not detect default interface, using eth0\n";
        defaultInterface = "eth0";
    }
    
    std::cout << "[TUNNEL] Setting up NAT for interface: " << defaultInterface << "\n";
    std::string subnetWithMask = subnet + ".0/24";
    
    tunInterface->executeCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");
    
    std::cout << "[TUNNEL] Cleaning up old rules...\n";
    tunInterface->executeCommand("iptables -t nat -D POSTROUTING -s " + subnetWithMask + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -s " + subnetWithMask + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -d " + subnetWithMask + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -i " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -o " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    
    std::cout << "[TUNNEL] Adding NAT MASQUERADE rule...\n";
    tunInterface->executeCommand("iptables -t nat -A POSTROUTING -s " + subnetWithMask + " -o " + defaultInterface + " -j MASQUERADE");
    
    std::cout << "[TUNNEL] Adding FORWARD rules...\n";
    tunInterface->executeCommand("iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -s " + subnetWithMask + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -d " + subnetWithMask + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -i " + interfaceName + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -o " + interfaceName + " -j ACCEPT");
    
    std::cout << "[TUNNEL] NAT configuration completed\n";
    
    tunInterface->executeCommand("iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE");
    tunInterface->executeCommand("iptables -L FORWARD -n -v | head -20");
}

void TunnelManager::start() {
    if (!tunInterface || !tunInterface->isOpened()) {
        std::cout << "[ERROR] TUN interface not ready\n";
        return;
    }
    
    tunnelThreadRunning = true;
    tunnelThread = std::thread(&TunnelManager::processPackets, this);
    std::cout << "[TUNNEL] Tunnel processing started\n";
}

void TunnelManager::stop() {
    std::cout << "[TUNNEL] Stopping tunnel manager...\n";
    
    tunnelThreadRunning = false;
    
    if (tunnelThread.joinable()) {
        tunnelThread.join();
    }
    
    // Cleanup NAT rules
    if (tunInterface) {
        cleanupNATRules();
    }
    
    std::cout << "[TUNNEL] Tunnel manager stopped\n";
}

void TunnelManager::processPackets() {
    char buffer[2048];
    std::cout << "[TUNNEL] Packet processing thread started\n";
    
    while (tunnelThreadRunning && tunInterface && tunInterface->isOpened()) {
        int bytesRead = tunInterface->readPacket(buffer, sizeof(buffer));
        
        if (bytesRead > 0) {
            std::cout << "[TUN->NET] Read " << bytesRead << " bytes from TUN\n";
            
            if (bytesRead >= 20) { // Minimum IP header size
                processIPPacket(buffer, bytesRead);
            }
        } else if (bytesRead == 0) {
            // No data available, continue
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else {
            // Error occurred
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                std::cout << "[ERROR] TUN read error: " << strerror(errno) << "\n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    std::cout << "[TUNNEL] Packet processing thread stopped\n";
}

void TunnelManager::processIPPacket(const char* packet, int size) {
    if (!packetHandler) return;
    
    struct iphdr {
        uint8_t version_ihl;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };
    
    iphdr* ip_header = (iphdr*)packet;
    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, 16);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, 16);
    
    std::cout << "[TUNNEL] Packet: " << src_ip << " -> " << dst_ip 
              << " (Protocol: " << (int)ip_header->protocol 
              << ", Size: " << size << " bytes)\n";
    
    // Xử lý packet thông qua PacketHandler
    packetHandler->handleTUNPacket(packet, size, std::string(src_ip), std::string(dst_ip));
}

bool TunnelManager::injectPacket(const char* packet, int size) {
    if (!tunInterface || !tunInterface->isOpened()) {
        return false;
    }
    
    int written = tunInterface->writePacket(packet, size);
    if (written > 0) {
        std::cout << "[NET->TUN] Injected " << written << " bytes into TUN\n";
        return true;
    } else {
        std::cout << "[ERROR] Failed to inject packet: " << strerror(errno) << "\n";
        return false;
    }
}

void TunnelManager::cleanupNATRules() {
    if (!tunInterface) return;
    
    std::cout << "[TUNNEL] Cleaning up NAT rules...\n";
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) defaultInterface = "eth0";
    
    std::string subnet = "10.8.0.0/24";
    tunInterface->executeCommand("iptables -t nat -D POSTROUTING -s " + subnet + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -s " + subnet + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -d " + subnet + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -i " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -o " + interfaceName + " -j ACCEPT 2>/dev/null || true");
}

TUNInterface* TunnelManager::getTUNInterface() const {
    return tunInterface;
}

bool TunnelManager::isRunning() const {
    return tunnelThreadRunning;
}

std::string TunnelManager::getInterfaceName() const {
    return interfaceName;
}

long long TunnelManager::getBytesReceived() const {
    return tunInterface ? tunInterface->getBytesReceived() : 0;
}

long long TunnelManager::getBytesSent() const {
    return tunInterface ? tunInterface->getBytesSent() : 0;
}