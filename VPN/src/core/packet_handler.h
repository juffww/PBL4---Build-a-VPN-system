#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <cstdint>

// Forward declarations
class TunnelManager;
class ClientManager;

// Packet statistics structure
struct PacketStats {
    long long totalPackets = 0;
    long long totalBytes = 0;
    long long packetsToClients = 0;
    long long bytesToClients = 0;
    long long packetsFromClients = 0;
    long long bytesFromClients = 0;
    long long packetsToInternet = 0;
    long long bytesToInternet = 0;
};

class PacketHandler {
private:
    TunnelManager* tunnelManager;
    ClientManager* clientManager;
    PacketStats packetStats;
    
    // Helper methods
    bool isVPNClient(const std::string& ip);
    void logPacketInfo(const char* packet, int size, const std::string& srcIP, 
                      const std::string& dstIP, const std::string& direction);
    std::string getProtocolName(uint8_t protocol);
    void logTCPInfo(const char* tcpHeader, int size);
    void logUDPInfo(const char* udpHeader, int size);
    void logICMPInfo(const char* icmpHeader, int size);
    void updatePacketStats(const std::string& direction, int bytes);

public:
    PacketHandler();
    ~PacketHandler();
    
    // Setup methods
    void setTunnelManager(TunnelManager* manager);
    void addClientManager(ClientManager* manager);
    
    // Packet handling methods
    void handleTUNPacket(const char* packet, int size, const std::string& srcIP, const std::string& dstIP);
    void handleClientPacket(int clientId, const char* packet, int size);
    void forwardPacketToClient(const char* packet, int size, const std::string& destIP);
    
    // Statistics
    PacketStats getPacketStats() const;
    void resetPacketStats();

    void debugRawPacket(const char* packet, int size);
    bool validateIPPacket(const char* packet, int size);
    std::string extractSourceIP(const char* packet);
    void handleValidatedPacket(const char* packet, int size,
                               const std::string& srcIP,
                               const std::string& dstIP);
    bool parsePacketIPs(const char* packet, std::string& srcIP, std::string& dstIP);
    void logProtocolDetails(const char* packet, int size);
    void logTCPDetails(const char* tcpHeader, int size);
    void logUDPDetails(const char* udpHeader, int size);
    void logICMPDetails(const char* icmpHeader, int size);
};

#endif // PACKET_HANDLER_H