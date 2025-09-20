#include "tunnel_manager.h"
#include <iostream>
#include <cstring>
#include <sstream>
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
#endif

TunnelManager::TunnelManager(const std::string& interface, const std::string& ip, const std::string& mask)
    : tunInterface(new TUNInterface(interface)), packetHandler(new PacketHandler()), running(false) {
    tunInterface->setIP(ip, mask);
    packetHandler->setTunnelManager(this);
}

TunnelManager::~TunnelManager() {
    stop();
    delete tunInterface;
    delete packetHandler;
}

bool TunnelManager::initialize() {
    if (!tunInterface->create()) {
        std::cout << "[ERROR] Failed to create TUN interface\n";
        return false;
    }

    if (!tunInterface->configure(tunInterface->getIP(), tunInterface->getMask(), "")) {
        std::cout << "[ERROR] Failed to configure TUN interface\n";
        return false;
    }

    if (!setupNATRules()) {
        std::cout << "[ERROR] Failed to setup NAT rules\n";
        return false;
    }

    return true;
}

void TunnelManager::start() {
    if (running) return;
    running = true;
    workerThread = std::thread(&TunnelManager::processTUN, this);
    std::cout << "[INFO] TunnelManager started\n";
}

void TunnelManager::stop() {
    running = false;
    if (workerThread.joinable()) {
        workerThread.join();
    }
    clearNATRules();
    tunInterface->close();
}

bool TunnelManager::setupNATRules() {
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) {
        std::cout << "[ERROR] Could not determine default interface\n";
        return false;
    }

    std::ostringstream cmd;
    cmd << "sysctl -w net.ipv4.ip_forward=1";
    if (!executeCommand(cmd.str())) {
        std::cout << "[ERROR] Failed to enable IP forwarding\n";
        return false;
    }

    executeCommand("iptables -F FORWARD");
    executeCommand("iptables -t nat -F POSTROUTING");

    cmd.str("");
    cmd << "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o " << defaultInterface << " -j MASQUERADE";
    if (!executeCommand(cmd.str())) {
        std::cout << "[ERROR] Failed to set NAT MASQUERADE rule\n";
        return false;
    }

    cmd.str("");
    cmd << "iptables -A FORWARD -i tun0 -j ACCEPT";
    if (!executeCommand(cmd.str())) {
        std::cout << "[ERROR] Failed to set FORWARD rule for tun0 input\n";
        return false;
    }

    cmd.str("");
    cmd << "iptables -A FORWARD -o tun0 -j ACCEPT";
    if (!executeCommand(cmd.str())) {
        std::cout << "[ERROR] Failed to set FORWARD rule for tun0 output\n";
        return false;
    }

    cmd.str("");
    cmd << "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT";
    if (!executeCommand(cmd.str())) {
        std::cout << "[ERROR] Failed to set FORWARD rule for RELATED,ESTABLISHED\n";
        return false;
    }

    std::cout << "[INFO] NAT and forwarding rules set up successfully\n";
    return true;
}

bool TunnelManager::clearNATRules() {
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) {
        std::cout << "[WARN] Could not determine default interface for clearing NAT rules\n";
        return false;
    }

    std::ostringstream cmd;
    cmd << "iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o " << defaultInterface << " -j MASQUERADE";
    executeCommand(cmd.str());

    cmd.str("");
    cmd << "iptables -D FORWARD -i tun0 -j ACCEPT";
    executeCommand(cmd.str());

    cmd.str("");
    cmd << "iptables -D FORWARD -o tun0 -j ACCEPT";
    executeCommand(cmd.str());

    cmd.str("");
    cmd << "iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT";
    executeCommand(cmd.str());

    executeCommand("iptables -F FORWARD");
    executeCommand("iptables -t nat -F POSTROUTING");

    std::cout << "[INFO] NAT and forwarding rules cleared\n";
    return true;
}

bool TunnelManager::executeCommand(const std::string& cmd) {
    std::cout << "[CMD] Executing: " << cmd << "\n";
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cout << "[WARN] Command failed with exit code: " << ret << "\n";
    }
    return (ret == 0);
}

void TunnelManager::processTUN() {
    char buffer[2000];
    while (running) {
        int n = tunInterface->readPacket(buffer, sizeof(buffer));
        if (n > 0) {
            std::cout << "[TUN->NET] Read " << n << " bytes from TUN\n";
            processIPPacket(buffer, n);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void TunnelManager::processIPPacket(const char* packet, int size) {
    if (size < 20) return;

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
    if ((ip_header->version_ihl & 0xF0) != 0x40) {
        std::cout << "[WARN] Dropping non-IPv4 packet\n";
        return;
    }

    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, 16);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, 16);

    std::cout << "[TUNNEL] Packet: " << src_ip << " -> " << dst_ip 
              << " (Protocol: " << (int)ip_header->protocol 
              << ", Size: " << size << " bytes)\n";

    packetHandler->handleTUNPacket(packet, size, src_ip, dst_ip);
}

bool TunnelManager::injectPacket(const char* packet, int size) {
    if (size < 20) return false;

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
    if ((ip_header->version_ihl & 0xF0) != 0x40) {
        std::cout << "[WARN] Dropping non-IPv4 packet for injection\n";
        return false;
    }

    int n = tunInterface->writePacket(packet, size);
    if (n > 0) {
        std::cout << "[NET->TUN] Injected " << n << " bytes to TUN\n";
        return true;
    } else {
        std::cout << "[ERROR] Failed to inject packet to TUN\n";
        return false;
    }
}

void TunnelManager::setClientManager(ClientManager* clientManager) {
    packetHandler->addClientManager(clientManager);
}

TUNInterface* TunnelManager::getTUNInterface() const {
    return tunInterface;
}