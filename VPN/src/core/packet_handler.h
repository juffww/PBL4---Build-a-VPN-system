#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <cstdint>

class TunnelManager;
class ClientManager;
class VPNServer; 

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
    VPNServer* vpnServer; 
    PacketStats packetStats;
    
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
    
    void setTunnelManager(TunnelManager* manager);
    void addClientManager(ClientManager* manager);
    void setVPNServer(VPNServer* server); // *** THÊM ***
    
    void handleTUNPacket(const char* packet, int size, const std::string& srcIP, const std::string& dstIP);
    void handleClientPacket(int clientId, const char* packet, int size);
    void forwardPacketToClient(const char* packet, int size, const std::string& destIP);
    
    PacketStats getPacketStats() const;
    void resetPacketStats();
};

#endif
