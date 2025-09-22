#ifndef VPN_SERVER_H
#define VPN_SERVER_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET SOCKET;
    #define INVALID_SOCKET INVALID_SOCKET
    #define SOCKET_ERROR SOCKET_ERROR
#else
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #include <ifaddrs.h>
#endif

// Include component headers
#include "client_manager.h"
#include "tunnel_manager.h"
#include "packet_handler.h"
#include "../network/tun_interface.h"

class VPNServer {
private:
    // Server configuration
    int serverPort;
    SOCKET serverSocket;
    std::atomic<bool> isRunning;
    std::atomic<bool> shouldStop;
    std::chrono::steady_clock::time_point startTime;
    
    // Component managers
    ClientManager* clientManager;
    TunnelManager* tunnelManager;
    PacketHandler* packetHandler;
    
    // Client handling threads
    std::vector<std::thread> clientThreads;
    
    // Private methods
    bool initializeServerSocket();
    void acceptConnections();
    void handleClient(int clientId);
    bool processClientMessage(int clientId, const std::string& message);
    
    // Command handlers
    bool handleAuthCommand(int clientId, std::istringstream& iss);
    bool handlePingCommand(int clientId);
    bool handleStatusCommand(int clientId);
    
    // Cleanup
    void cleanup();

public:
    explicit VPNServer(int port = 1194);
    ~VPNServer();
    
    // Core server operations
    bool initialize();
    void start();
    void stop();
    
    // Server information
    int getPort() const;
    int getClientCount() const;
    std::string getServerIP() const;
    long long getUptime() const;
    
    // Client management
    std::vector<ClientInfo> getConnectedClients() const;
    bool disconnectClient(int clientId);
    std::vector<std::string> getAllAssignedVPNIPs() const;
    
    // Network interface access
    TUNInterface* getTUNInterface() const;
    
    // Statistics
    std::vector<std::string> getVPNStats();

    ClientManager* getClientManager() const { return clientManager; }
    PacketHandler* getPacketHandler() const { return packetHandler; }
    std::vector<std::string> getPacketStats();

};

#endif // VPN_SERVER_H