// #ifndef VPN_SERVER_H
// #define VPN_SERVER_H

// #include <string>
// #include <map>
// #include <vector>
// #include <thread>
// #include <mutex>
// #include <chrono>
// #include <atomic>
// #include <queue>
// #include "real_vpn_server.h"

// #ifdef _WIN32
//     #include <winsock2.h>
//     #define SOCKET_ERROR -1
//     #define INVALID_SOCKET -1
//     typedef int SOCKET;
// #else
//     #define SOCKET int
//     #define INVALID_SOCKET -1
//     #define SOCKET_ERROR -1
// #endif

// struct ClientInfo {
//     int id;
//     SOCKET socket;
//     std::string ip;
//     int port;
//     std::string connectTime;
//     std::chrono::steady_clock::time_point connectedAt;
//     bool authenticated;
//     std::string username;
    
//     // VPN specific fields
//     std::string assignedVpnIP;
//     std::string realIP;
//     bool ipAssigned;
// };

// class IPPool {
// private:
//     std::queue<std::string> availableIPs;
//     std::map<std::string, bool> ipUsage;
//     std::mutex poolMutex;
//     std::string baseNetwork;
    
// public:
//     IPPool(const std::string& network = "10.8.0", int startRange = 2, int endRange = 254);
//     std::string assignIP();
//     void releaseIP(const std::string& ip);
//     int getAvailableCount();
//     std::vector<std::string> getAllAssignedIPs();
// };

// class VPNServer {
// private:
//     int serverPort;
//     SOCKET serverSocket;
//     std::atomic<bool> isRunning;
//     std::atomic<bool> shouldStop;
//     int nextClientId;
    
//     std::map<int, ClientInfo> clients;
//     mutable std::mutex clientsMutex;
//     std::vector<std::thread> clientThreads;
//     std::chrono::steady_clock::time_point startTime;
    
//     IPPool ipPool;

// public:
//     VPNServer(int port);
//     ~VPNServer();

//     bool initialize(); //Tạo socket với cổng 1194
//     void start();
//     void stop();
    
//     void acceptConnections(); //Lắng nghe client kết nối
//     void handleClient(int clientId); //Xử lý clients trong thread riêng
//     bool authenticateClient(int clientId, const std::string& username, const std::string& password);
    
//     void sendToClient(int clientId, const std::string& message);
//     void broadcastToClients(const std::string& message);
//     void removeClient(int clientId);
    
//     std::string getCurrentTime();
//     int getClientCount() const;
//     std::string getServerIP() const;
//     long long getUptime() const;
//     std::vector<ClientInfo> getConnectedClients() const;
//     bool disconnectClient(int clientId);
    
//     int getPort() const { return serverPort; }
    
//     // VPN specific methods
//     bool assignVPNIP(int clientId);
//     void releaseVPNIP(int clientId);
//     std::string getClientVPNIP(int clientId);
//     std::vector<std::string> getVPNStats();

//     std::vector<std::string> getAllAssignedVPNIPs() {
//         return ipPool.getAllAssignedIPs();
//     }
// };
#ifndef VPN_SERVER_H
#define VPN_SERVER_H

#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <queue>
#include <sstream>
#include "network/tun_interface.h"

#ifdef _WIN32
    #include <winsock2.h>
    #define SOCKET_ERROR -1
    #define INVALID_SOCKET -1
    typedef SOCKET SOCKET;
#else
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

struct ClientInfo {
    int id;
    SOCKET socket;
    std::string ip;
    int port;
    std::string connectTime;
    std::chrono::steady_clock::time_point connectedAt;
    bool authenticated;
    std::string username;
    
    // VPN specific fields
    std::string assignedVpnIP;
    std::string realIP;
    bool ipAssigned;
};

class IPPool {
private:
    std::queue<std::string> availableIPs;
    std::map<std::string, bool> ipUsage;
    std::mutex poolMutex;
    std::string baseNetwork;
    
public:
    IPPool(const std::string& network = "10.8.0", int startRange = 2, int endRange = 254);
    std::string assignIP();
    void releaseIP(const std::string& ip);
    int getAvailableCount();
    std::vector<std::string> getAllAssignedIPs();
};

class VPNServer {
private:
    int serverPort;
    SOCKET serverSocket;
    std::atomic<bool> isRunning;
    std::atomic<bool> shouldStop;
    int nextClientId;
    
    std::map<int, ClientInfo> clients;
    mutable std::mutex clientsMutex;
    std::vector<std::thread> clientThreads;
    std::chrono::steady_clock::time_point startTime;
    
    IPPool ipPool;

    // 🔹 Thêm TUN interface
    TUNInterface* tunInterface;

public:
    VPNServer(int port);
    ~VPNServer();

    bool initialize();
    void start();
    void stop();
    
    void acceptConnections();
    void handleClient(int clientId);
    bool authenticateClient(int clientId, const std::string& username, const std::string& password);
    
    void sendToClient(int clientId, const std::string& message);
    void broadcastToClients(const std::string& message);
    void removeClient(int clientId);
    
    std::string getCurrentTime();
    int getClientCount() const;
    std::string getServerIP() const;
    long long getUptime() const;
    std::vector<ClientInfo> getConnectedClients() const;
    bool disconnectClient(int clientId);
    
    int getPort() const { return serverPort; }
    
    // VPN specific methods
    bool assignVPNIP(int clientId);
    void releaseVPNIP(int clientId);
    std::string getClientVPNIP(int clientId);
    std::vector<std::string> getVPNStats();

    std::vector<std::string> getAllAssignedVPNIPs() {
        return ipPool.getAllAssignedIPs();
    }

    // 🔹 Getter cho TUN
    TUNInterface* getTUNInterface() { return tunInterface; }
};

#endif // VPN_SERVER_H
