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

void PacketHandler::handleTUNPacket(const char* packet, int size, const std::string& srcIP, const std::string& dstIP) {
    if (!clientManager) {
        return;
    }
    
    if (srcIP == "10.8.0.1" && (dstIP.substr(0, 4) == "224." || dstIP.substr(0, 4) == "239.")) {
        return;
    }
    
    // SERVER -> CLIENT
    if (srcIP == "10.8.0.1" && isVPNClient(dstIP)) {
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
    
    // CLIENT -> SERVER
    if (isVPNClient(srcIP) && dstIP == "10.8.0.1") {
        updatePacketStats("FROM_CLIENT", size);
        return;
    }
    
    // CLIENT -> INTERNET
    if (isVPNClient(srcIP) && !isVPNClient(dstIP) && dstIP != "10.8.0.1") {
        updatePacketStats("TO_INTERNET", size);
        return;
    }
    
    // INTERNET -> CLIENT
    if (!isVPNClient(srcIP) && srcIP != "10.8.0.1" && isVPNClient(dstIP)) {
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
    
    // INTER-CLIENT
    if (isVPNClient(srcIP) && isVPNClient(dstIP)) {
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
    
    // Try UDP first
    struct sockaddr_in clientAddr;
    if (vpnServer->getClientUDPAddr(clientId, clientAddr)) {
        char buffer[8192];
        
        // if (size + 8 > sizeof(buffer)) {
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
    }
    
    // TCP Fallback
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (client && client->socket != INVALID_SOCKET) {
        std::string header = "PACKET_DATA|" + std::to_string(size) + "\n";
        
        if (send(client->socket, header.c_str(), header.length(), MSG_NOSIGNAL) > 0) {
            int sent = send(client->socket, packet, size, MSG_NOSIGNAL);
            if (sent > 0) {
                clientManager->updateClientStats(clientId, size, 0);
            }
        }
    }
}

bool PacketHandler::isVPNClient(const std::string& ip) {
    return (ip.substr(0, 6) == "10.8.0" && ip != "10.8.0.1");
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

void PacketHandler::updatePacketStats(const std::string& direction, int bytes) {
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