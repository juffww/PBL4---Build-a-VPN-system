// real_vpn_server.h
#ifndef REAL_VPN_SERVER_H
#define REAL_VPN_SERVER_H

#include "vpn_server.h"
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

// Thêm vào ClientInfo struct
struct PacketStats {
    quint64 bytesReceived = 0;
    quint64 bytesSent = 0;
    quint64 packetsReceived = 0;
    quint64 packetsSent = 0;
    std::chrono::steady_clock::time_point lastActivity;
    
    PacketStats() : lastActivity(std::chrono::steady_clock::now()) {}
};

// Enhanced ClientInfo
struct EnhancedClientInfo : public ClientInfo {
    PacketStats stats;
    std::queue<std::vector<uint8_t>> packetQueue;
    std::mutex packetQueueMutex;
};

class RealVPNServer : public VPNServer {
private:
    std::map<int, EnhancedClientInfo> enhancedClients;
    std::thread packetForwardingThread;
    bool packetForwardingRunning;
    std::mutex packetMutex;
    std::condition_variable packetCV;

public:
    RealVPNServer(int port = 1194);
    virtual ~RealVPNServer();
    
    // Override base methods
    virtual void handleClient(int clientId) override;
    virtual void removeClient(int clientId) override;
    
    // New methods for packet handling
    void startPacketForwarding();
    void stopPacketForwarding();
    void processPacketForwarding();
    void forwardPacket(int fromClientId, const std::vector<uint8_t>& packet);
    void routePacketToDestination(const std::vector<uint8_t>& packet, int sourceClientId);
    std::string getDestinationIP(const std::vector<uint8_t>& packet);
    int findClientByVpnIP(const std::string& vpnIP);
    
    // Statistics
    PacketStats getClientStats(int clientId);
    void updateClientStats(int clientId, size_t bytes, bool sent);
    std::vector<std::pair<int, PacketStats>> getAllClientStats();
};
#endif 