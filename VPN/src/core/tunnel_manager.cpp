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
    std::cout << "[TUNNEL] Initializing...\n";
    
    packetHandler = handler;
    
    tunInterface = new TUNInterface(interfaceName);
    if (!tunInterface->create()) {
        std::cout << "[ERROR] Cannot create TUN interface\n";
        return false;
    }
    
    if (!tunInterface->configure(serverIP, "24", "", true)) {
        std::cout << "[ERROR] Cannot configure TUN interface\n";
        return false;
    }
    
    tunInterface->executeCommand("ip link set dev " + interfaceName + " mtu 1400");
    std::cout << "[TUNNEL] MTU set to 1400\n";

    setupVPNRouting(subnet);
    
    std::cout << "[TUNNEL] Ready: " << tunInterface->getName() 
              << " (" << tunInterface->getIP() << "/" << tunInterface->getMask() << ")\n";
    
    return true;
}

void TunnelManager::setupVPNRouting(const std::string& subnet) {
    std::string routeCmd = "ip route add " + subnet + "/24 dev " + tunInterface->getName() + " 2>/dev/null || true";
    tunInterface->executeCommand(routeCmd);
    
    setupNATRules(subnet);
}

void TunnelManager::setupNATRules(const std::string& subnet) {
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) {
        defaultInterface = "eth0";
    }
    
    std::string subnetWithMask = subnet + ".0/24";
    
    tunInterface->executeCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");
    
    tunInterface->executeCommand("iptables -t nat -D POSTROUTING -s " + subnetWithMask + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -s " + subnetWithMask + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -d " + subnetWithMask + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -i " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -o " + interfaceName + " -j ACCEPT 2>/dev/null || true");

    tunInterface->executeCommand("iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true");
    
    tunInterface->executeCommand("iptables -t nat -A POSTROUTING -s " + subnetWithMask + " -o " + defaultInterface + " -j MASQUERADE");

    tunInterface->executeCommand("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu");

    tunInterface->executeCommand("iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -s " + subnetWithMask + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -d " + subnetWithMask + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -i " + interfaceName + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -o " + interfaceName + " -j ACCEPT");
    
    std::cout << "[TUNNEL] NAT configured for " << defaultInterface << "\n";
}

void TunnelManager::start() {
    if (!tunInterface || !tunInterface->isOpened()) {
        std::cout << "[ERROR] TUN interface not ready\n";
        return;
    }
    
    tunnelThreadRunning = true;
    tunnelThread = std::thread(&TunnelManager::processPackets, this);
    std::cout << "[TUNNEL] Processing started\n";
}

void TunnelManager::stop() {
    tunnelThreadRunning = false;
    
    if (tunnelThread.joinable()) {
        tunnelThread.join();
    }
    
    if (tunInterface) {
        cleanupNATRules();
    }
}

void TunnelManager::processPackets() {
    char buffer[65536]; 
    int consecutiveErrors = 0;
    const int maxErrors = 10;
    
    while (tunnelThreadRunning && tunInterface && tunInterface->isOpened()) {
        int bytesRead = tunInterface->readPacket(buffer, sizeof(buffer));
        
        if (bytesRead > 0) {
            consecutiveErrors = 0; 
            if (bytesRead >= 20) {
                processIPPacket(buffer, bytesRead);
            }
        } else if (bytesRead == 0 || (bytesRead < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            //std::this_thread::sleep_for(std::chrono::microseconds(100));
        } else {
            consecutiveErrors++;
            if (consecutiveErrors >= maxErrors) {
                std::cout << "[ERROR] Too many TUN read errors, stopping\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
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
    
    packetHandler->handleTUNPacket(packet, size, std::string(src_ip), std::string(dst_ip));
}

bool TunnelManager::injectPacket(const char* packet, int size) {
    if (!tunInterface || !tunInterface->isOpened()) {
        return false;
    }
    
    int written = tunInterface->writePacket(packet, size);
    return (written > 0);
}

void TunnelManager::cleanupNATRules() {
    if (!tunInterface) return;
    
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) defaultInterface = "eth0";
    
    std::string subnet = "10.8.0.0/24";
    tunInterface->executeCommand("iptables -t nat -D POSTROUTING -s " + subnet + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -s " + subnet + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -d " + subnet + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -i " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -o " + interfaceName + " -j ACCEPT 2>/dev/null || true");

    tunInterface->executeCommand("iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true");
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