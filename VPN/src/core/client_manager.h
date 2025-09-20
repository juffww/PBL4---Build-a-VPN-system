#ifndef CLIENT_MANAGER_H
#define CLIENT_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <mutex>
#include <chrono>
#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET SOCKET;
    #define INVALID_SOCKET INVALID_SOCKET
    #define SOCKET_ERROR SOCKET_ERROR
#else
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

// Forward declaration
class PacketHandler;

// Client information structure
struct ClientInfo {
    int id;
    SOCKET socket;
    std::string realIP;
    int port;
    std::string connectTime;
    std::chrono::steady_clock::time_point connectedAt;
    bool authenticated;
    std::string username;
    bool ipAssigned;
    std::string assignedVpnIP;
    long long bytesSent;
    long long bytesReceived;
    
    ClientInfo() : id(-1), socket(INVALID_SOCKET), port(0), authenticated(false), 
                   ipAssigned(false), bytesSent(0), bytesReceived(0) {}
};

// IP Pool management class
class IPPool {
private:
    std::string baseNetwork;
    std::queue<std::string> availableIPs;
    std::map<std::string, bool> ipUsage;
    mutable std::mutex poolMutex;

public:
    IPPool(const std::string& network, int startRange, int endRange);
    
    std::string assignIP();
    void releaseIP(const std::string& ip);
    int getAvailableCount();
    std::vector<std::string> getAllAssignedIPs() const;
};

// Client Manager class
class ClientManager {
private:
    std::map<int, ClientInfo> clients;
    mutable std::mutex clientsMutex;
    int nextClientId;
    IPPool* ipPool;
    PacketHandler* packetHandler;
    
    std::string getCurrentTime();

public:
    ClientManager();
    ~ClientManager();
    
    // Setup
    void setPacketHandler(PacketHandler* handler);
    
    // Client management
    int addClient(SOCKET socket, const std::string& realIP, int port);
    bool removeClient(int clientId);
    bool disconnectClient(int clientId);
    
    // Authentication and IP assignment
    bool authenticateClient(int clientId, const std::string& username, const std::string& password);
    bool assignVPNIP(int clientId);
    void releaseVPNIP(int clientId);
    std::string getClientVPNIP(int clientId);
    int findClientByVPNIP(const std::string& vpnIP);
    
    // Communication
    bool sendToClient(int clientId, const std::string& message);
    void broadcastToClients(const std::string& message);
    void handleClientPacket(int clientId, const char* packet, int size);
    
    // Statistics and information
    void updateClientStats(int clientId, long long bytesSent, long long bytesReceived);
    std::vector<ClientInfo> getConnectedClients() const;
    int getClientCount() const;
    std::vector<std::string> getAllAssignedVPNIPs() const;
    int getAvailableIPs() const;
    
    // Client information
    ClientInfo* getClientInfo(int clientId);
    bool isClientAuthenticated(int clientId);
    bool hasVPNIP(int clientId);
    
    // Cleanup
    void cleanup();
    std::vector<std::string> getClientStats();

    // Thêm vào class ClientManager
    void disconnectAllClients();
    SOCKET getClientSocket(int clientId) const;

};

#endif // CLIENT_MANAGER_H