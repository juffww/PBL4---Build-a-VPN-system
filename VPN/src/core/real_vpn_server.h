// // real_vpn_server.h - Updated header
// #ifndef REAL_VPN_SERVER_H
// #define REAL_VPN_SERVER_H

// #include "vpn_server.h"
// #include <thread>
// #include <queue>
// #include <condition_variable>
// #include <atomic>

// class TUNInterface; // Forward declaration

// struct PacketStats {
//     uint64_t bytesReceived = 0;
//     uint64_t bytesSent = 0;
//     uint32_t packetsReceived = 0;
//     uint32_t packetsSent = 0;
//     std::chrono::steady_clock::time_point lastActivity;
// };

// struct EnhancedClientInfo {
//     // Base client info
//     SOCKET socket = INVALID_SOCKET;
//     std::string address;
//     bool authenticated = false;
//     std::string username;
//     bool ipAssigned = false;
//     std::string assignedVpnIP;
//     std::chrono::steady_clock::time_point connectionTime;
    
//     // Enhanced info for packet handling
//     PacketStats stats;
//     std::queue<std::vector<uint8_t>> packetQueue;
//     std::mutex packetQueueMutex;
// };

// class RealVPNServer : public VPNServer {
// private:
//     TUNInterface* tun;
//     std::atomic<bool> packetForwardingRunning;
//     std::thread packetForwardingThread;
//     std::thread tunReadThread;
    
//     std::mutex packetMutex;
//     std::condition_variable packetCV;
//     std::map<int, EnhancedClientInfo> enhancedClients;

// public:
//     RealVPNServer(int port = 1194);
//     virtual ~RealVPNServer();
    
//     // Override client handling
//     void handleClient(int clientId) override;
//     void removeClient(int clientId) override;
    
//     // Packet forwarding
//     void startPacketForwarding();
//     void stopPacketForwarding();
//     void processPacketForwarding();
//     void readFromTUN();
//     void forwardPacket(int fromClientId, const std::vector<uint8_t>& packet);
    
//     // Utility methods
//     std::string getDestinationIP(const std::vector<uint8_t>& packet);
//     int findClientByVpnIP(const std::string& vpnIP);
    
//     // Statistics
//     PacketStats getClientStats(int clientId);
//     void updateClientStats(int clientId, size_t bytes, bool sent);
//     std::vector<std::pair<int, PacketStats>> getAllClientStats();
    
//     // Base64 encoding/decoding
//     std::string base64_encode(const std::vector<uint8_t>& data);
//     std::vector<uint8_t> base64_decode(const std::string& encoded);
// };

// #endif // REAL_VPN_SERVER_H