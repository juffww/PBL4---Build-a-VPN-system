#include "packet_handler.h"
#include "client_manager.h"
#include "tunnel_manager.h"
#include "vpn_server.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <string>
#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip_icmp.h>
#endif

PacketHandler::PacketHandler() : tunnelManager(nullptr) {
}

PacketHandler::~PacketHandler() {
}

void PacketHandler::setTunnelManager(TunnelManager* manager) {
    tunnelManager = manager;
}

void PacketHandler::addClientManager(ClientManager* manager) {
    clientManager = manager;
}

void PacketHandler::setVPNServer(VPNServer* server) {
    vpnServer = server;
}

// OPTIMIZATION: Inline and cache-friendly IP check
inline bool PacketHandler::isVPNClient(const std::string& ip) {
    // Fast string comparison - check first 6 chars
    return (ip.size() >= 8 && ip[0] == '1' && ip[1] == '0' && 
            ip[2] == '.' && ip[3] == '8' && ip[4] == '.' && 
            ip[5] == '0' && ip != "10.8.0.1");
}

void PacketHandler::handleTUNPacket(const char* packet, int size, const std::string& srcIP, const std::string& dstIP) {
    if (!clientManager) {
        return;
    }
    
    // OPTIMIZATION: Quick multicast filter - avoid string operations
    if (srcIP[0] == '1' && srcIP[1] == '0' && dstIP[0] == '2') {
        return; // Skip multicast packets
    }
    
    bool srcIsVPNClient = isVPNClient(srcIP);
    bool dstIsVPNClient = isVPNClient(dstIP);
    bool srcIsServer = (srcIP == "10.8.0.1");
    bool dstIsServer = (dstIP == "10.8.0.1");
    
    // SERVER -> CLIENT
    if (srcIsServer && dstIsVPNClient) {
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
    
    // CLIENT -> SERVER
    if (srcIsVPNClient && dstIsServer) {
        updatePacketStats("FROM_CLIENT", size);
        return;
    }
    
    // CLIENT -> INTERNET
    if (srcIsVPNClient && !dstIsVPNClient && !dstIsServer) {
        updatePacketStats("TO_INTERNET", size);
        return;
    }
    
    // INTERNET -> CLIENT or INTER-CLIENT
    if ((!srcIsVPNClient && !srcIsServer && dstIsVPNClient) || 
        (srcIsVPNClient && dstIsVPNClient)) {
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
}

void PacketHandler::handleClientPacket(int clientId, const char* packet, int size) {
    if (!tunnelManager) {
        return;
    }
    updatePacketStats("FROM_CLIENT", size);

    tunnelManager->injectPacket(packet, size);
    
    if (clientManager) {
        clientManager->updateClientStats(clientId, 0, size);
    }
}

void PacketHandler::forwardPacketToClient(const char* packet, int size, const std::string& destIP) {
    if (!clientManager || !vpnServer) {
        return;
    }
    
    if (size <= 0 || size > 1500) {
        return;
    }
    
    int clientId = clientManager->findClientByVPNIP(destIP);
    if (clientId == -1) {
        return;
    }
    
    // ===== STRATEGY 1: UDP ONLY (Recommended) =====
    // Chỉ dùng UDP, bỏ qua nếu thất bại
    struct sockaddr_in clientAddr;
    if (vpnServer->getClientUDPAddr(clientId, clientAddr)) {
        char buffer[8192];
        
        if (static_cast<size_t>(size + 8) > sizeof(buffer)){
            return;
        }
        
        *(int*)buffer = clientId;
        *(int*)(buffer + 4) = size;
        memcpy(buffer + 8, packet, size);
        
        int totalSize = size + 8;
        int sent = sendto(vpnServer->getUDPSocket(), buffer, totalSize, 0,
                         (struct sockaddr*)&clientAddr, sizeof(clientAddr));
        
        if (sent == totalSize) {
            clientManager->updateClientStats(clientId, size, 0);
            return;
        }
        
        // OPTIMIZATION: Không fallback TCP, chỉ log lỗi (silent)
        // UDP packet loss là bình thường, TCP sẽ retransmit ở tầng trên
        static int udpFailCount = 0;
        if (++udpFailCount % 1000 == 0) {
            std::cerr << "[WARN] UDP send failures: " << udpFailCount << std::endl;
        }
        return;
    }
    
    // ===== STRATEGY 2: TCP CHỈ KHI UDP CHƯA READY =====
    // Chỉ dùng TCP trong giai đoạn handshake/setup
    // Sau khi UDP ready, bỏ qua TCP hoàn toàn
    
    // KHÔNG NÊN có code TCP fallback ở đây nữa!
    // Lý do:
    // - UDP packet loss < 1% là chấp nhận được
    // - TCP retransmission sẽ xử lý ở tầng application
    // - Giảm complexity và latency
}

std::string PacketHandler::getProtocolName(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_IP:   return "IP";
        default: return "UNKNOWN(" + std::to_string(protocol) + ")";
    }
}

PacketStats PacketHandler::getPacketStats() const {
    return packetStats;
}

void PacketHandler::resetPacketStats() {
    packetStats = PacketStats();
}

// OPTIMIZATION: Reduce atomic operations overhead
inline void PacketHandler::updatePacketStats(const std::string& direction, int bytes) {
    if (direction == "TO_CLIENT") {
        packetStats.packetsToClients++;
        packetStats.bytesToClients += bytes;
    } else if (direction == "FROM_CLIENT") {
        packetStats.packetsFromClients++;
        packetStats.bytesFromClients += bytes;
    } else if (direction == "TO_INTERNET") {
        packetStats.packetsToInternet++;
        packetStats.bytesToInternet += bytes;
    }
    packetStats.totalPackets++;
    packetStats.totalBytes += bytes;
}