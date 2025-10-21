#include "vpn_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include "client_manager.h" 
#include "tunnel_manager.h"
#include "packet_handler.h"
#ifdef _WIN32
    #include <ws2tcpip.h>
    #define close closesocket
    #define MSG_NOSIGNAL 0
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <errno.h>
#endif

VPNServer::VPNServer(int port) 
    : serverPort(port), serverSocket(INVALID_SOCKET), isRunning(false), 
      shouldStop(false), clientManager(nullptr), tunnelManager(nullptr), 
      packetHandler(nullptr) {
}

VPNServer::~VPNServer() {
    stop();
    cleanup();
}

bool VPNServer::initialize() {    
    std::cout << "[SERVER] Initializing...\n";
    
    clientManager = new ClientManager();
    tunnelManager = new TunnelManager("tun0");
    packetHandler = new PacketHandler();
    
    packetHandler->addClientManager(clientManager);
    packetHandler->setTunnelManager(tunnelManager);
    packetHandler->setVPNServer(this); 
    clientManager->setPacketHandler(packetHandler);
    
    if (!tunnelManager->initialize("10.8.0.1", "10.8.0", packetHandler)) {
        std::cout << "[ERROR] Tunnel initialization failed\n";
        return false;
    }
    
    if (!initializeServerSocket()) {
        std::cout << "[ERROR] Cannot initialize server socket\n";
        return false;
    }
    
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] Cannot create UDP socket\n";
        return false;
    }
    
    struct sockaddr_in udpAddr;
    memset(&udpAddr, 0, sizeof(udpAddr));
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_addr.s_addr = INADDR_ANY;
    udpAddr.sin_port = htons(5502);
    
    if (bind(udpSocket, (struct sockaddr*)&udpAddr, sizeof(udpAddr)) < 0) {
        std::cout << "[ERROR] Cannot bind UDP socket\n";
        return false;
    }
    
    std::cout << "[SERVER] Ready on TCP:" << serverPort << " UDP:5502\n";
    
    return true;
}

bool VPNServer::initializeServerSocket() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] Cannot create socket\n";
        return false;
    }
    
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) < 0) {
        std::cout << "[WARN] Cannot set SO_REUSEADDR\n";
    }
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverPort);
    
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "[ERROR] Cannot bind socket on port " << serverPort << "\n";
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }
    
    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        std::cout << "[ERROR] Cannot listen on socket\n";
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }
    
    return true;
}

void VPNServer::start() {
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] Server not initialized\n";
        return;
    }
    
    isRunning = true;
    shouldStop = false;
    startTime = std::chrono::steady_clock::now();
    
    tunnelManager->start();
    
    udpThread = std::thread(&VPNServer::handleUDPPackets, this);
    
    std::cout << "[INFO] ========================================\n";
    std::cout << "[INFO] VPN Server Started Successfully!\n";
    std::cout << "[INFO] TCP Control Port: " << serverPort << "\n";
    std::cout << "[INFO] UDP Data Port: 5502\n";
    std::cout << "[INFO] Server VPN IP: 10.8.0.1/24\n";
    std::cout << "[INFO] Client IP Range: 10.8.0.2 - 10.8.0.254\n";
    std::cout << "[INFO] ========================================\n";
    
    acceptConnections();
}

// Replace the handleUDPPackets() function in vpn_server.cpp with this optimized version:

void VPNServer::handleUDPPackets() {
    char buffer[65536]; // Larger buffer for batch processing
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    
    // OPTIMIZATION: Reduce timeout for better responsiveness
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms timeout
    setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    
    // OPTIMIZATION: Increase UDP buffer sizes
    int rcvbuf = 2097152; // 2MB
    int sndbuf = 2097152; // 2MB
    setsockopt(udpSocket, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    setsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
    
    while (!shouldStop) {
        int n = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&clientAddr, &addrLen);
        
        if (n > 0) {
            if (n >= 8) {
                int clientId = *(int*)buffer;
                int dataSize = *(int*)(buffer + 4);
                
                // Quick validation
                if (clientId <= 0 || clientId > 1000) {
                    continue;
                }
                
                // HANDSHAKE
                if (dataSize == 0) {
                    {
                        std::lock_guard<std::mutex> lock(udpAddrMutex);
                        clientUDPAddrs[clientId] = clientAddr;
                    }
                    
                    char ack[8];
                    *(int*)ack = clientId;
                    *(int*)(ack + 4) = 0;
                    
                    sendto(udpSocket, ack, 8, 0, 
                          (struct sockaddr*)&clientAddr, sizeof(clientAddr));
                    continue;
                }
                
                // DATA PACKET - with validation
                if (dataSize > 0 && dataSize <= (n - 8) && dataSize < 65536) {
                    {
                        std::lock_guard<std::mutex> lock(udpAddrMutex);
                        clientUDPAddrs[clientId] = clientAddr;
                    }
                    
                    if (clientManager) {
                        // OPTIMIZATION: Direct packet handling without copying
                        clientManager->handleClientPacket(clientId, buffer + 8, dataSize);
                    }
                }
            }
        }
        // Remove error logging for performance
    }
}

bool VPNServer::getClientUDPAddr(int clientId, struct sockaddr_in& addr) {
    std::lock_guard<std::mutex> lock(udpAddrMutex);
    auto it = clientUDPAddrs.find(clientId);
    if (it != clientUDPAddrs.end()) {
        addr = it->second;
        return true;
    }
    return false;
}

void VPNServer::acceptConnections() {
    while (!shouldStop && isRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        
        if (clientSocket == INVALID_SOCKET) {
            if (!shouldStop) {
                std::cout << "[ERROR] Accept connection error\n";
            }
            continue;
        }
        
        std::string clientIP = inet_ntoa(clientAddr.sin_addr);
        int clientPort = ntohs(clientAddr.sin_port);
        
        int clientId = clientManager->addClient(clientSocket, clientIP, clientPort);
        
        clientThreads.emplace_back([this, clientId]() {
            handleClient(clientId);
        });
    }
}

void VPNServer::handleClient(int clientId) {
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (!client) return;

    char buffer[4096];
    std::string welcomeMsg = "WELCOME|VPN Server 2.0.0|Ready for authentication\n";
    clientManager->sendToClient(clientId, welcomeMsg);

    std::string messageBuffer;
    bool expectingPacketData = false;
    int packetSizeToRead = 0;

    while (!shouldStop && client->socket != INVALID_SOCKET) {
        int bytesReceived = recv(client->socket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            break;
        }

        messageBuffer.append(buffer, bytesReceived);

        bool processedData = true;
        while(processedData) {
            processedData = false;
            if (expectingPacketData) {
                if (messageBuffer.length() >= static_cast<size_t>(packetSizeToRead)){
                    clientManager->handleClientPacket(clientId, messageBuffer.data(), packetSizeToRead);

                    messageBuffer.erase(0, packetSizeToRead);
                    expectingPacketData = false;
                    packetSizeToRead = 0;
                    processedData = true; 
                }
            } else {
                size_t pos = messageBuffer.find('\n');
                if (pos != std::string::npos) {
                    std::string message = messageBuffer.substr(0, pos);
                    messageBuffer.erase(0, pos + 1);

                    if (message.rfind("PACKET_DATA|", 0) == 0) {
                        if (clientManager->isClientAuthenticated(clientId)) {
                            try {
                                packetSizeToRead = std::stoi(message.substr(12));
                                if (packetSizeToRead > 0 && packetSizeToRead < 4096) {
                                    expectingPacketData = true;
                                }
                            } catch (const std::exception&) { }
                        }
                    } else {
                        if (!processClientMessage(clientId, message)) {
                            goto end_loop;
                        }
                    }
                    processedData = true; 
                }
            }
        }
    }

end_loop:
    clientManager->removeClient(clientId);
}

bool VPNServer::processClientMessage(int clientId, const std::string& message) {
    std::istringstream iss(message);
    std::string command;
    iss >> command;
    
    if (command == "AUTH") {
        return handleAuthCommand(clientId, iss);
    }
    else if (command == "PING") {
        return handlePingCommand(clientId);
    }
    else if (command == "GET_STATUS") {
        return handleStatusCommand(clientId);
    }
    else if (command == "DISCONNECT") {
        clientManager->sendToClient(clientId, "BYE|Goodbye\n");
        return false; 
    }
    else {
        if (!clientManager->isClientAuthenticated(clientId)) {
            clientManager->sendToClient(clientId, "ERROR|Please authenticate first\n");
        } else {
            clientManager->sendToClient(clientId, "ERROR|Unknown command\n");
        }
    }
    
    return true;
}

bool VPNServer::handleAuthCommand(int clientId, std::istringstream& iss) {
    std::string username, password;
    iss >> username >> password;
    
    if (clientManager->authenticateClient(clientId, username, password)) {
        if (clientManager->assignVPNIP(clientId)) {
            std::string vpnIP = clientManager->getClientVPNIP(clientId);
            
            ClientInfo* client = clientManager->getClientInfo(clientId);
            std::string serverRealIP = "0.0.0.0";
            if (client && client->socket != INVALID_SOCKET) {
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                if (getsockname(client->socket, (struct sockaddr*)&addr, &addr_len) == 0) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
                    serverRealIP = std::string(ip);
                }
            }
            
            std::string response = "AUTH_OK|Authentication successful|VPN_IP:" + vpnIP + 
                     "|SERVER_IP:10.8.0.1|SUBNET:10.8.0.0/24"
                     "|SERVER_REAL_IP:" + serverRealIP + 
                     "|UDP_PORT:5502" +
                     "|CLIENT_ID:" + std::to_string(clientId) + "\n";
                     
            clientManager->sendToClient(clientId, response);
        } else {
            clientManager->sendToClient(clientId, "AUTH_FAIL|No VPN IP available\n");
        }
    } else {
        clientManager->sendToClient(clientId, "AUTH_FAIL|Invalid credentials\n");
    }
    
    return true;
}

bool VPNServer::handlePingCommand(int clientId) {
    std::string pongMsg = "PONG|" + std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) + "\n";
    clientManager->sendToClient(clientId, pongMsg);
    return true;
}

bool VPNServer::handleStatusCommand(int clientId) {
    if (clientManager->isClientAuthenticated(clientId)) {
        std::string vpnIP = clientManager->getClientVPNIP(clientId);
        ClientInfo* client = clientManager->getClientInfo(clientId);
        
        std::string status = "STATUS|Connected|VPN_IP:" + vpnIP + 
                           "|SERVER_IP:10.8.0.1|CLIENTS:" + std::to_string(getClientCount());
        
        if (client) {
            status += "|BYTES_SENT:" + std::to_string(client->bytesSent) +
                     "|BYTES_RECV:" + std::to_string(client->bytesReceived);
        }
        
        status += "\n";
        clientManager->sendToClient(clientId, status);
    } else {
        clientManager->sendToClient(clientId, "ERROR|Not authenticated\n");
    }
    return true;
}

void VPNServer::stop() {
    std::cout << "[SERVER] Stopping...\n";
    
    shouldStop = true;
    isRunning = false;
    
    if (tunnelManager) {
        tunnelManager->stop();
    }
    
    if (serverSocket != INVALID_SOCKET) {
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    
    if (udpSocket != INVALID_SOCKET) {
        close(udpSocket);
        udpSocket = INVALID_SOCKET;
    }
    
    if (udpThread.joinable()) {
        udpThread.join();
    }
    
    for (auto& thread : clientThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    clientThreads.clear();
    
    std::cout << "[SERVER] Stopped\n";
}

void VPNServer::cleanup() {
    if (clientManager) {
        delete clientManager;
        clientManager = nullptr;
    }
    
    if (tunnelManager) {
        delete tunnelManager;
        tunnelManager = nullptr;
    }
    
    if (packetHandler) {
        delete packetHandler;
        packetHandler = nullptr;
    }
}

int VPNServer::getPort() const {
    return serverPort;
}

int VPNServer::getClientCount() const {
    return clientManager ? clientManager->getClientCount() : 0;
}

std::string VPNServer::getServerIP() const {
    #ifdef _WIN32
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            struct hostent* host = gethostbyname(hostname);
            if (host) {
                return std::string(inet_ntoa(*((struct in_addr*)host->h_addr)));
            }
        }
    #else
        struct ifaddrs* ifaddrs_ptr;
        if (getifaddrs(&ifaddrs_ptr) == 0) {
            for (struct ifaddrs* ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                    std::string addr = inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr);
                    if (addr != "127.0.0.1" && addr.substr(0, 6) != "10.8.0") {
                        freeifaddrs(ifaddrs_ptr);
                        return addr;
                    }
                }
            }
            freeifaddrs(ifaddrs_ptr);
        }
    #endif
    return "127.0.0.1";
}

long long VPNServer::getUptime() const {
    if (!isRunning) return 0;
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - startTime);
    return duration.count();
}

std::vector<ClientInfo> VPNServer::getConnectedClients() const {
    return clientManager ? clientManager->getConnectedClients() : std::vector<ClientInfo>();
}

bool VPNServer::disconnectClient(int clientId) {
    return clientManager ? clientManager->disconnectClient(clientId) : false;
}

std::vector<std::string> VPNServer::getAllAssignedVPNIPs() const {
    return clientManager ? clientManager->getAllAssignedVPNIPs() : std::vector<std::string>();
}

TUNInterface* VPNServer::getTUNInterface() const {
    return tunnelManager ? tunnelManager->getTUNInterface() : nullptr;
}

std::vector<std::string> VPNServer::getPacketStats() {
    std::vector<std::string> stats;
    
    if (packetHandler) {
        PacketStats pStats = packetHandler->getPacketStats();
        stats.push_back("Packet Processing Statistics:");
        stats.push_back("============================");
        stats.push_back("Total Packets Processed: " + std::to_string(pStats.totalPackets));
        stats.push_back("Total Bytes Processed: " + std::to_string(pStats.totalBytes));
        stats.push_back("");
        stats.push_back("Traffic Distribution:");
        stats.push_back("  To Clients: " + std::to_string(pStats.packetsToClients) + 
                        " packets (" + std::to_string(pStats.bytesToClients) + " bytes)");
        stats.push_back("  From Clients: " + std::to_string(pStats.packetsFromClients) + 
                        " packets (" + std::to_string(pStats.bytesFromClients) + " bytes)");
        stats.push_back("  To Internet: " + std::to_string(pStats.packetsToInternet) + 
                        " packets (" + std::to_string(pStats.bytesToInternet) + " bytes)");
        
        if (pStats.totalPackets > 0) {
            stats.push_back("");
            stats.push_back("Percentage Distribution:");
            stats.push_back("  To Clients: " + 
                          std::to_string((pStats.packetsToClients * 100) / pStats.totalPackets) + "%");
            stats.push_back("  From Clients: " + 
                          std::to_string((pStats.packetsFromClients * 100) / pStats.totalPackets) + "%");  
            stats.push_back("  To Internet: " + 
                          std::to_string((pStats.packetsToInternet * 100) / pStats.totalPackets) + "%");
        }
    } else {
        stats.push_back("Packet handler not available");
    }
    
    return stats;
}

std::vector<std::string> VPNServer::getVPNStats() {
    std::vector<std::string> stats;
    stats.push_back("VPN Server Statistics:");
    stats.push_back("======================");
    stats.push_back("Server VPN IP: 10.8.0.1/24");
    
    if (clientManager) {
        stats.push_back("Available IPs: " + std::to_string(clientManager->getAvailableIPs()));
        
        auto assignedIPs = clientManager->getAllAssignedVPNIPs();
        stats.push_back("Assigned IPs: " + std::to_string(assignedIPs.size()));
        
        if (!assignedIPs.empty()) {
            stats.push_back("Assigned IP List:");
            for (const auto& ip : assignedIPs) {
                stats.push_back("  - " + ip);
            }
        }
        
        stats.push_back("Connected Clients: " + std::to_string(clientManager->getClientCount()));
    }
    
    if (tunnelManager) {
        TUNInterface* tun = tunnelManager->getTUNInterface();
        if (tun) {
            stats.push_back("TUN Interface: " + tun->getName());
            stats.push_back("TUN Bytes Received: " + std::to_string(tun->getBytesReceived()));
            stats.push_back("TUN Bytes Sent: " + std::to_string(tun->getBytesSent()));
        }
    }
    
    return stats;
}