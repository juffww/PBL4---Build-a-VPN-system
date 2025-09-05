// // // include/vpn_server.h
// // #pragma once
// // #include <memory>
// // #include <thread>
// // #include <atomic>
// // #include <unordered_map>
// // #include <mutex>
// // #include <openssl/evp.h>
// // #include <linux/if_tun.h>

// // class VPNServer {
// // private:
// //     std::atomic<bool> running_{false};
// //     int tun_fd_{-1};
// //     int server_socket_{-1};
    
// //     std::unique_ptr<std::thread> packet_thread_;
// //     std::unique_ptr<std::thread> client_thread_;
// //     std::unique_ptr<std::thread> web_thread_;
    
// //     // Client management
// //     struct ClientSession {
// //         uint32_t client_id;
// //         std::string public_key;
// //         std::string ip_address;
// //         time_t last_seen;
// //         uint64_t bytes_sent;
// //         uint64_t bytes_received;
// //         EVP_CIPHER_CTX* encrypt_ctx;
// //         EVP_CIPHER_CTX* decrypt_ctx;
// //     };
    
// //     std::unordered_map<uint32_t, std::unique_ptr<ClientSession>> clients_;
// //     std::mutex clients_mutex_;

// // public:
// //     VPNServer();
// //     ~VPNServer();
    
// //     bool Initialize();
// //     void Start();
// //     void Stop();
    
// // private:
// //     bool CreateTunInterface();
// //     bool SetupServerSocket();
// //     void PacketProcessingLoop();
// //     void ClientHandlingLoop();
// //     void WebServerLoop();
    
// //     bool ProcessIncomingPacket(const uint8_t* data, size_t len, uint32_t client_id);
// //     bool ProcessOutgoingPacket(const uint8_t* data, size_t len);
    
// //     bool AuthenticateClient(const std::string& public_key, uint32_t& client_id);
// //     bool EncryptPacket(ClientSession* client, const uint8_t* input, 
// //                       size_t input_len, uint8_t* output, size_t& output_len);
// //     bool DecryptPacket(ClientSession* client, const uint8_t* input,
// //                       size_t input_len, uint8_t* output, size_t& output_len);
// // };
// #ifndef VPN_SERVER_H
// #define VPN_SERVER_H

// #include <string>
// #include <vector>
// #include <map>
// #include <mutex>
// #include <thread>
// #include <atomic>
// #include <chrono>

// #ifdef _WIN32
//     #include <winsock2.h>
//     typedef int socklen_t;
// #else
//     #include <sys/socket.h>
//     #include <netinet/in.h>
//     typedef int SOCKET;
//     #define INVALID_SOCKET -1
//     #define SOCKET_ERROR -1
// #endif

// struct ClientInfo {
//     int id;
//     SOCKET socket;
//     std::string ip;
//     int port;
//     std::string connectTime;
//     bool authenticated;
//     std::chrono::steady_clock::time_point connectedAt;
    
//     ClientInfo() : id(0), socket(INVALID_SOCKET), port(0), authenticated(false) {}
// };

// class VPNServer {
// private:
//     int serverPort;
//     SOCKET serverSocket;
//     bool isRunning;
//     std::atomic<bool> shouldStop;
    
//     // Client management
//     std::map<int, ClientInfo> clients;
//     // std::mutex clientsMutex;
//     mutable std::mutex clientsMutex;

//     int nextClientId;
    
//     // Statistics
//     std::chrono::steady_clock::time_point startTime;
    
//     // Threads
//     std::vector<std::thread> clientThreads;
    
//     // Private methods
//     void acceptConnections();
//     void handleClient(int clientId);
//     bool authenticateClient(int clientId, const std::string& username, const std::string& password);
//     void sendToClient(int clientId, const std::string& message);
//     void broadcastToClients(const std::string& message);
//     void removeClient(int clientId);
//     std::string getCurrentTime();
    
// public:
//     VPNServer(int port = 1194);
//     ~VPNServer();
    
//     bool initialize();
//     void start();
//     void stop();
    
//     // Getters
//     bool isServerRunning() const { return isRunning; }
//     int getPort() const { return serverPort; }
//     int getClientCount() const;
//     std::string getServerIP() const;
//     long long getUptime() const;
    
//     // Client management
//     std::vector<ClientInfo> getConnectedClients() const;
//     bool disconnectClient(int clientId);
    
//     // Configuration
//     void setPort(int port) { serverPort = port; }
// };

// #endif // VPN_SERVER_H
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

#ifdef _WIN32
    #include <winsock2.h>
    #define SOCKET_ERROR -1
    #define INVALID_SOCKET -1
    typedef int SOCKET;
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
};

#endif // VPN_SERVER_H