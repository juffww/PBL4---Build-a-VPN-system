#ifndef VPN_SERVER_H
#define VPN_SERVER_H

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include <map>
#include <mutex>
#include <openssl/rand.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET SOCKET;
    #define INVALID_SOCKET INVALID_SOCKET
    #define SOCKET_ERROR SOCKET_ERROR
#else
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #include <ifaddrs.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif

#include "../crypto/tls_wrapper.h"
#include "client_manager.h"
#include "tunnel_manager.h"
#include "packet_handler.h"
#include "../network/tun_interface.h"

class TunnelManager;
class PacketHandler;
class TUNInterface;
struct sockaddr_in;

class VPNServer {
private:
    // UDP support
    SOCKET udpSocket;
    std::thread udpThread;
    std::map<int, struct sockaddr_in> clientUDPAddrs;
    std::mutex udpAddrMutex;

    std::string certFile;
    std::string keyFile;
    
    void handleUDPPackets();
    
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
    
    bool initializeServerSocket();
    void acceptConnections();
    void handleClient(int clientId);
    bool processClientMessage(int clientId, const std::string& message);
    
    // Command handlers
    // bool handleAuthCommand(int clientId, std::istringstream& iss);
    bool handleAuthCommand(int clientId);
    bool handlePingCommand(int clientId);
    bool handleStatusCommand(int clientId);
    
    // Cleanup
    void cleanup();

public:
    explicit VPNServer(int port = 5000, 
                   const std::string& cert = "certs/server.crt", 
                   const std::string& key = "certs/server.key");
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
    ClientManager* getClientManager() const { return clientManager; }
    PacketHandler* getPacketHandler() const { return packetHandler; }
    
    // UDP access for PacketHandler
    SOCKET getUDPSocket() const { return udpSocket; }
    bool getClientUDPAddr(int clientId, struct sockaddr_in& addr);

    //TLS
    void sendTLS(int clientId, const std::string& message);

    void cleanupFinishedThreads();
};

#endif