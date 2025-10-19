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
        std::cout << "[PACKET] No client manager available\n";
        return;
    }
    
    if (srcIP == "10.8.0.1" && (dstIP.substr(0, 4) == "224." || dstIP.substr(0, 4) == "239.")) {
        return;
    }
    
    // === SERVER -> CLIENT ===
    if (srcIP == "10.8.0.1" && isVPNClient(dstIP)) {
        std::cout << "[PACKET] Server->Client: " << srcIP << " -> " << dstIP 
                  << " (" << size << " bytes)\n";
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
    
    // === CLIENT -> SERVER ===
    if (isVPNClient(srcIP) && dstIP == "10.8.0.1") {
        std::cout << "[PACKET] Client->Server: " << srcIP << " -> " << dstIP 
                  << " (" << size << " bytes)\n";
        updatePacketStats("FROM_CLIENT", size);
        return;
    }
    
    // === CLIENT -> INTERNET ===
    if (isVPNClient(srcIP) && !isVPNClient(dstIP) && dstIP != "10.8.0.1") {
        std::cout << "[PACKET] Client->Internet: " << srcIP << " -> " << dstIP 
                  << " (" << size << " bytes)\n";
        updatePacketStats("TO_INTERNET", size);
        logPacketInfo(packet, size, srcIP, dstIP, "TO_INTERNET");
        return;
    }
    
    // === INTERNET -> CLIENT ===
    if (!isVPNClient(srcIP) && srcIP != "10.8.0.1" && isVPNClient(dstIP)) {
        std::cout << "[PACKET] Internet->Client: " << srcIP << " -> " << dstIP 
                  << " (" << size << " bytes)\n";
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
    
    // === INTER-CLIENT ===
    if (isVPNClient(srcIP) && isVPNClient(dstIP)) {
        std::cout << "[PACKET] Inter-client: " << srcIP << " -> " << dstIP 
                  << " (" << size << " bytes)\n";
        forwardPacketToClient(packet, size, dstIP);
        updatePacketStats("TO_CLIENT", size);
        return;
    }
    
    std::cout << "[PACKET] Unhandled: " << srcIP << " -> " << dstIP << "\n";
}

void PacketHandler::handleClientPacket(int clientId, const char* packet, int size) {
    if (!tunnelManager) {
        std::cout << "[PACKET] No tunnel manager available\n";
        return;
    }
    updatePacketStats("FROM_CLIENT", size);

    if (size >= 20) {
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
        
        std::cout << "[PACKET] Client " << clientId << " packet: " 
                  << src_ip << " -> " << dst_ip 
                  << " (Protocol: " << (int)ip_header->protocol 
                  << ", Size: " << size << " bytes)\n";
        
        logPacketInfo(packet, size, std::string(src_ip), std::string(dst_ip), "FROM_CLIENT");
    }
    
    if (tunnelManager->injectPacket(packet, size)) {
        std::cout << "[PACKET] Successfully injected packet from client " << clientId << " into TUN\n";
        
        if (clientManager) {
            clientManager->updateClientStats(clientId, 0, size); 
        }
    } else {
        std::cout << "[ERROR] Failed to inject packet from client " << clientId << "\n";
    }
}

// void PacketHandler::forwardPacketToClient(const char* packet, int size, const std::string& destIP) {
//     if (!clientManager || !vpnServer) {
//         std::cout << "[ERROR] Missing dependencies for packet forwarding\n";
//         return;
//     }
    
//     if (size <= 0 || size > 1500) {
//         std::cout << "[WARN] Invalid packet size: " << size << "\n";
//         return;
//     }
    
//     int clientId = clientManager->findClientByVPNIP(destIP);
//     if (clientId == -1) {
//         std::cout << "[WARN] No client found for VPN IP: " << destIP << "\n";
//         return;
//     }
    
//     // Thử gửi qua UDP trước
//     struct sockaddr_in clientAddr;
//     if (vpnServer->getClientUDPAddr(clientId, clientAddr)) {
//         char buffer[8192];
        
//         if (size + 8 > sizeof(buffer)) {
//             std::cout << "[ERROR] Packet too large for UDP buffer\n";
//             return;
//         }
        
//         *(int*)buffer = clientId;
//         *(int*)(buffer + 4) = size;
//         memcpy(buffer + 8, packet, size);
        
//         int totalSize = size + 8;
//         int sent = sendto(vpnServer->getUDPSocket(), buffer, totalSize, 0,
//                          (struct sockaddr*)&clientAddr, sizeof(clientAddr));
        
//         if (sent == totalSize) {
//             static int udpSentCount = 0;
//             if (++udpSentCount % 50 == 0) {
//                 char ip[INET_ADDRSTRLEN];
//                 inet_ntop(AF_INET, &clientAddr.sin_addr, ip, INET_ADDRSTRLEN);
//                 std::cout << "[UDP->CLIENT] Sent " << udpSentCount 
//                           << " packets (" << size << " bytes) to client " << clientId 
//                           << " at " << ip << ":" << ntohs(clientAddr.sin_port) << "\n";
//             }
//             clientManager->updateClientStats(clientId, size, 0);
//             return; 
//         } else {
//             std::cout << "[WARN] UDP send failed (sent=" << sent << ", expected=" << totalSize 
//                       << "): " << strerror(errno) << ", using TCP fallback\n";
//         }
//     }
    
//     // TCP Fallback
//     ClientInfo* client = clientManager->getClientInfo(clientId);
//     if (client && client->socket != INVALID_SOCKET) {
//         std::string header = "PACKET_DATA|" + std::to_string(size) + "\n";
        
//         if (send(client->socket, header.c_str(), header.length(), MSG_NOSIGNAL) > 0) {
//             int sent = send(client->socket, packet, size, MSG_NOSIGNAL);
//             if (sent > 0) {
//                 static int tcpSentCount = 0;
//                 if (++tcpSentCount % 50 == 0) {
//                     std::cout << "[TCP->CLIENT] Sent " << tcpSentCount 
//                               << " packets (" << size << " bytes) to client " 
//                               << clientId << " (fallback)\n";
//                 }
//                 clientManager->updateClientStats(clientId, size, 0);
//             } else {
//                 std::cout << "[ERROR] TCP send failed: " << strerror(errno) << "\n";
//             }
//         } else {
//             std::cout << "[ERROR] TCP header send failed: " << strerror(errno) << "\n";
//         }
//     } else {
//         std::cout << "[ERROR] Client " << clientId << " socket invalid\n";
//     }
// }
// Thay thế hàm forwardPacketToClient() trong packet_handler.cpp:

void PacketHandler::forwardPacketToClient(const char* packet, int size, const std::string& destIP) {
    if (!clientManager || !vpnServer) {
        std::cout << "[ERROR] Missing dependencies for packet forwarding\n";
        return;
    }
    
    if (size <= 0 || size > 1500) {
        std::cout << "[WARN] Invalid packet size: " << size << "\n";
        return;
    }
    
    int clientId = clientManager->findClientByVPNIP(destIP);
    if (clientId == -1) {
        std::cout << "[WARN] No client found for VPN IP: " << destIP << "\n";
        return;
    }
    
    // Thử gửi qua UDP trước
    struct sockaddr_in clientAddr;
    if (vpnServer->getClientUDPAddr(clientId, clientAddr)) {
        char buffer[8192];
        
        if (size + 8 > sizeof(buffer)) {
            std::cout << "[ERROR] Packet too large for UDP buffer\n";
            return;
        }
        
        *(int*)buffer = clientId;
        *(int*)(buffer + 4) = size;
        memcpy(buffer + 8, packet, size);
        
        int totalSize = size + 8;
        int sent = sendto(vpnServer->getUDPSocket(), buffer, totalSize, 0,
                         (struct sockaddr*)&clientAddr, sizeof(clientAddr));
        
        if (sent == totalSize) {
            static int udpSentCount = 0;
            if (++udpSentCount % 10 == 0) { // Giảm xuống 10 để thấy log sớm hơn
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, ip, INET_ADDRSTRLEN);
                std::cout << "[UDP->CLIENT] ✓ Sent " << udpSentCount 
                          << " packets (" << size << " bytes) to client " << clientId 
                          << " at " << ip << ":" << ntohs(clientAddr.sin_port) << "\n";
            }
            clientManager->updateClientStats(clientId, size, 0);
            return;
        } else {
            std::cout << "[UDP->CLIENT] ✗ Send failed (sent=" << sent << ", expected=" << totalSize 
                      << "): " << strerror(errno) << "\n";
        }
    } else {
        std::cout << "[UDP->CLIENT] ✗ No UDP address for client " << clientId << "\n";
    }
    
    // TCP Fallback
    std::cout << "[TCP->CLIENT] Using TCP fallback for client " << clientId << "\n";
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

void PacketHandler::logPacketInfo(const char* packet, int size, const std::string& srcIP, const std::string& dstIP, const std::string& direction) {
    //if (size < 20) return;
    
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
    std::string protocolName = getProtocolName(ip_header->protocol);
    
    std::cout << "[PACKET_LOG] " << direction << " - " 
              << srcIP << " -> " << dstIP 
              << " | " << protocolName 
              << " | " << size << " bytes"
              << " | TTL:" << (int)ip_header->ttl << "\n";
    
    if (ip_header->protocol == IPPROTO_TCP && size >= 40) {
        logTCPInfo(packet + 20, size - 20);
    } else if (ip_header->protocol == IPPROTO_UDP && size >= 28) {
        logUDPInfo(packet + 20, size - 20);
    } else if (ip_header->protocol == IPPROTO_ICMP && size >= 28) {
        logICMPInfo(packet + 20, size - 20);
    }
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

void PacketHandler::logTCPInfo(const char* tcpHeader, int size) {
    //if (size < 20) return;
    
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t flags;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
    };
    
    tcphdr* tcp = (tcphdr*)tcpHeader;
    uint16_t srcPort = ntohs(tcp->source);
    uint16_t dstPort = ntohs(tcp->dest);
    
    std::cout << "[TCP_DETAIL] Port " << srcPort << " -> " << dstPort;
    
    // Parse TCP flags
    uint8_t flags = (tcp->flags >> 8) & 0xFF;
    if (flags & 0x02) std::cout << " [SYN]";
    if (flags & 0x10) std::cout << " [ACK]";
    if (flags & 0x01) std::cout << " [FIN]";
    if (flags & 0x04) std::cout << " [RST]";
    if (flags & 0x08) std::cout << " [PSH]";
    
    std::cout << "\n";
}

void PacketHandler::logUDPInfo(const char* udpHeader, int size) {
    //if (size < 8) return;
    
    struct udphdr {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    };
    
    udphdr* udp = (udphdr*)udpHeader;
    uint16_t srcPort = ntohs(udp->source);
    uint16_t dstPort = ntohs(udp->dest);
    uint16_t length = ntohs(udp->len);
    
    std::cout << "[UDP_DETAIL] Port " << srcPort << " -> " << dstPort 
              << " | Length: " << length << " bytes\n";
}

void PacketHandler::logICMPInfo(const char* icmpHeader, int size) {
    //if (size < 8) return;
    
    struct icmphdr {
        uint8_t type;
        uint8_t code;
        uint16_t checksum;
        uint16_t id;
        uint16_t sequence;
    };
    
    icmphdr* icmp = (icmphdr*)icmpHeader;
    
    std::string icmpType;
    switch (icmp->type) {
        case 0:  icmpType = "Echo Reply"; break;
        case 3:  icmpType = "Destination Unreachable"; break;
        case 8:  icmpType = "Echo Request"; break;
        case 11: icmpType = "Time Exceeded"; break;
        default: icmpType = "Type " + std::to_string(icmp->type);
    }
    
    std::cout << "[ICMP_DETAIL] " << icmpType << " | Code: " << (int)icmp->code;
    if (icmp->type == 0 || icmp->type == 8) {
        std::cout << " | ID: " << ntohs(icmp->id) << " | Seq: " << ntohs(icmp->sequence);
    }
    std::cout << "\n";
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