#include "vpn_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <algorithm>
#ifdef _WIN32
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <ifaddrs.h>
#endif

IPPool::IPPool(const std::string& network, int startRange, int endRange) 
    : baseNetwork(network) {
    for (int i = startRange; i <= endRange; i++) {
        std::string ip = baseNetwork + "." + std::to_string(i);
        availableIPs.push(ip);
        ipUsage[ip] = false;
    }
}

std::string IPPool::assignIP() {
    std::lock_guard<std::mutex> lock(poolMutex);
    if (availableIPs.empty()) {
        return ""; 
    }
    
    std::string assignedIP = availableIPs.front();
    availableIPs.pop();
    ipUsage[assignedIP] = true;
    
    return assignedIP;
}

void IPPool::releaseIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(poolMutex);
    auto it = ipUsage.find(ip);
    if (it != ipUsage.end() && it->second) {
        it->second = false;
        availableIPs.push(ip);
    }
}

int IPPool::getAvailableCount() {
    std::lock_guard<std::mutex> lock(poolMutex);
    return availableIPs.size();
}

std::vector<std::string> IPPool::getAllAssignedIPs() const{
    std::lock_guard<std::mutex> lock(poolMutex);
    std::vector<std::string> assigned;
    for (const auto& pair : ipUsage) {
        if (pair.second) {
            assigned.push_back(pair.first);
        }
    }
    
    return assigned;
}

VPNServer::VPNServer(int port) 
    : serverPort(port), serverSocket(INVALID_SOCKET), isRunning(false), 
      shouldStop(false), nextClientId(1), tunInterface(nullptr), tunThreadRunning(false) {
}

VPNServer::~VPNServer() {
    stop();
    if (tunInterface) {
        delete tunInterface;
        tunInterface = nullptr;
    }
}

bool VPNServer::initialize() {
    tunInterface = new TUNInterface("tun0");
    if (!tunInterface->create()) {
        std::cout << "[ERROR] KhÃ´ng thá»ƒ táº¡o TUN interface\n";
        return false;
    }
    if (!tunInterface->configure("10.8.0.1", "24", "", true)) {
        std::cout << "[ERROR] KhÃ´ng thá»ƒ cáº¥u hÃ¬nh TUN interface\n";
        return false;
    }
    std::cout << "[INFO] TUN interface Ä‘Ã£ sáºµn sÃ ng: "
              << tunInterface->getName() << " ("
              << tunInterface->getIP() << "/" << tunInterface->getMask() << ")\n";

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] KhÃ´ng thá»ƒ táº¡o socket\n";
        return false;
    }
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) < 0) {
        std::cout << "[WARN] KhÃ´ng thá»ƒ set SO_REUSEADDR\n";
    }
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverPort);
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "[ERROR] KhÃ´ng thá»ƒ bind socket trÃªn cá»•ng " << serverPort << "\n";
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }
    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        std::cout << "[ERROR] KhÃ´ng thá»ƒ listen trÃªn socket\n";
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }
    return true;
}

void VPNServer::start() {
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] Server chÆ°a Ä‘Æ°á»£c khá»Ÿi táº¡o\n";
        return;
    }
    isRunning = true;
    shouldStop = false;
    startTime = std::chrono::steady_clock::now();
    startTUNProcessing();
    std::cout << "[INFO] VPN Server Ä‘ang láº¯ng nghe káº¿t ná»‘i...\n";
    std::cout << "[INFO] IP Pool: " << ipPool.getAvailableCount() << " IPs available\n";
    acceptConnections();
}

void VPNServer::startTUNProcessing() {
    tunThreadRunning = true;
    tunThread = std::thread([this]() {
        char buffer[2048];
        std::cout << "[INFO] TUN processing thread started\n";
        while (tunThreadRunning && tunInterface && tunInterface->isOpened()) {
            int bytesRead = tunInterface->readPacket(buffer, sizeof(buffer));
            if (bytesRead > 0) {
                std::cout << "[DEBUG] TUN read " << bytesRead << " bytes\n";
                if (bytesRead >= 20) { 
                    struct iphdr {
                        uint8_t version_ihl;
                        uint8_t tos;
                        uint16_t tot_len;
                        uint16_t id;
                        uint16_t frag_off;
                        uint8_t ttl;
                        uint8_t protocol;
                        uint16_t check;
                        uint32_t saddr;
                        uint32_t daddr;
                    };
                    iphdr* ip_header = (iphdr*)buffer;
                    char src_ip[16], dst_ip[16];
                    inet_ntop(AF_INET, &ip_header->saddr, src_ip, 16);
                    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, 16);
                    std::cout << "[TUN] Packet: " << src_ip << " -> " << dst_ip 
                              << " (" << bytesRead << " bytes)\n";
                    forwardPacketToClient(buffer, bytesRead, std::string(dst_ip));
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::cout << "[INFO] TUN processing thread stopped\n";
    });
}

void VPNServer::forwardPacketToClient(const char* packet, int size, const std::string& destIP) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& pair : clients) {
        if (pair.second.authenticated && pair.second.ipAssigned && 
            pair.second.assignedVpnIP == destIP) {
            std::string packetData = "PACKET|";
            packetData.append(packet, size);
            packetData += "\n";
            if (send(pair.second.socket, packetData.c_str(), packetData.length(), MSG_NOSIGNAL) > 0) {
                std::cout << "[FORWARD] Packet sent to client " << pair.first 
                          << " (VPN IP: " << destIP << ")\n";
            }
            return;
        }
    }
    std::cout << "[INFO] Packet to " << destIP << " - forwarding to internet\n";
}

void VPNServer::injectPacketFromClient(int clientId, const char* packet, int size) {
    if (tunInterface && tunInterface->isOpened()) {
        int written = tunInterface->writePacket(packet, size);
        if (written > 0) {
            std::cout << "[INJECT] " << written << " bytes injected to TUN from client " 
                      << clientId << "\n";
        }
    }
}

void VPNServer::stop() {
    shouldStop = true;
    isRunning = false;
    tunThreadRunning = false;
    if (tunThread.joinable()) {
        tunThread.join();
    }
    if (serverSocket != INVALID_SOCKET) {
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        for (auto& pair : clients) {
            if (pair.second.socket != INVALID_SOCKET) {
                close(pair.second.socket);
            }
            if (pair.second.ipAssigned) {
                ipPool.releaseIP(pair.second.assignedVpnIP);
            }
        }
        clients.clear();
    }
    for (auto& thread : clientThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    clientThreads.clear();
    if (tunInterface) {
        std::cout << "[INFO] ÄÃ³ng TUN interface\n";
        delete tunInterface;
        tunInterface = nullptr;
    }
}

void VPNServer::acceptConnections() {
    while (!shouldStop && isRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            if (!shouldStop) {
                std::cout << "[ERROR] Lá»—i khi accept connection\n";
            }
            continue;
        }
        ClientInfo clientInfo;
        clientInfo.id = nextClientId++;
        clientInfo.socket = clientSocket;
        clientInfo.ip = inet_ntoa(clientAddr.sin_addr);
        clientInfo.port = ntohs(clientAddr.sin_port);
        clientInfo.connectTime = getCurrentTime();
        clientInfo.connectedAt = std::chrono::steady_clock::now();
        clientInfo.authenticated = false;
        clientInfo.realIP = clientInfo.ip;
        clientInfo.ipAssigned = false;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients[clientInfo.id] = clientInfo;
        }
        std::cout << "[INFO] Client má»›i káº¿t ná»‘i - ID: " << clientInfo.id 
                  << ", Real IP: " << clientInfo.ip << ":" << clientInfo.port << "\n";

        clientThreads.emplace_back([this, clientInfo]() {
            handleClient(clientInfo.id);
        });
    }
}

void VPNServer::handleClient(int clientId) {
    ClientInfo* client = nullptr;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        auto it = clients.find(clientId);
        if (it != clients.end()) {
            client = &it->second;
        }
    }
    if (!client) return;
    char buffer[2048];
    std::string welcomeMsg = "WELCOME|VPN Server 1.0.0|Ready for authentication\n";
    send(client->socket, welcomeMsg.c_str(), welcomeMsg.length(), 0);
    while (!shouldStop && client->socket != INVALID_SOCKET) {
        int bytesReceived = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            break;
        }
        buffer[bytesReceived] = '\0';
        std::string message(buffer);
        std::istringstream iss(message);
        std::string command;
        iss >> command;
        if (command == "AUTH") {
            std::string username, password;
            iss >> username >> password;
            if (authenticateClient(clientId, username, password)) {
                client->authenticated = true;
                client->username = username;
                if (assignVPNIP(clientId)) {
                    std::string response = "AUTH_OK|Authentication successful|VPN_IP:" + client->assignedVpnIP + "\n";
                    sendToClient(clientId, response);
                    std::cout << "[INFO] Client " << clientId << " authenticated, assigned VPN IP: " 
                              << client->assignedVpnIP << "\n";
                } else {
                    sendToClient(clientId, "AUTH_FAIL|No VPN IP available\n");
                    std::cout << "[WARN] Client " << clientId << " authentication failed - no IP available\n";
                }
            } else {
                sendToClient(clientId, "AUTH_FAIL|Invalid credentials\n");
                std::cout << "[WARN] Client " << clientId << " authentication failed\n";
            }
        }
        else if (command == "PACKET") {
            if (client->authenticated && bytesReceived > 7) { 
                const char* packetData = buffer + 7; 
                int packetSize = bytesReceived - 7;
                std::cout << "[RECV] Packet from client " << clientId 
                          << " (" << packetSize << " bytes)\n";
                
                injectPacketFromClient(clientId, packetData, packetSize);
            }
        }
        else if (command == "PING") {
            sendToClient(clientId, "PONG\n");
        }
        else if (command == "GET_IP") {
            if (client->authenticated && client->ipAssigned) {
                std::string ipInfo = "VPN_IP|" + client->assignedVpnIP + "|" + getServerIP() + "\n";
                sendToClient(clientId, ipInfo);
            } else {
                sendToClient(clientId, "ERROR|Not authenticated or no IP assigned\n");
            }
        }
        else if (command == "DISCONNECT") {
            sendToClient(clientId, "BYE|Goodbye\n");
            break;
        }
        else if (client->authenticated) {
            if (command == "STATUS") {
                std::string status = "STATUS|Connected|VPN_IP:" + client->assignedVpnIP + 
                                   "|Clients:" + std::to_string(getClientCount()) + "\n";
                sendToClient(clientId, status);
            }
            else if (command == "DATA") {
                std::cout << "[DEBUG] Data tá»« client " << clientId << ": " << message << "\n";
                sendToClient(clientId, "ACK|Data received\n");
            }
        }
        else {
            sendToClient(clientId, "ERROR|Please authenticate first\n");
        }
    }
    std::cout << "[INFO] Client " << clientId << " disconnected\n";
    removeClient(clientId);
}

bool VPNServer::authenticateClient(int clientId, const std::string& username, const std::string& password) {
    return !username.empty() && !password.empty();
}

bool VPNServer::assignVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it == clients.end()) return false;
    std::string assignedIP = ipPool.assignIP();
    if (assignedIP.empty()) {
        return false;
    }
    it->second.assignedVpnIP = assignedIP;
    it->second.ipAssigned = true;
    return true;
}

void VPNServer::releaseVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.ipAssigned) {
        ipPool.releaseIP(it->second.assignedVpnIP);
        it->second.ipAssigned = false;
        it->second.assignedVpnIP.clear();
    }
}

std::string VPNServer::getClientVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.ipAssigned) {
        return it->second.assignedVpnIP;
    }
    return "";
}

void VPNServer::sendToClient(int clientId, const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.socket != INVALID_SOCKET) {
        send(it->second.socket, message.c_str(), message.length(), 0);
    }
}

void VPNServer::broadcastToClients(const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& pair : clients) {
        if (pair.second.socket != INVALID_SOCKET && pair.second.authenticated) {
            send(pair.second.socket, message.c_str(), message.length(), 0);
        }
    }
}

void VPNServer::removeClient(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        if (it->second.socket != INVALID_SOCKET) {
            close(it->second.socket);
        }
        
        if (it->second.ipAssigned) {
            ipPool.releaseIP(it->second.assignedVpnIP);
            std::cout << "[INFO] Released VPN IP: " << it->second.assignedVpnIP << "\n";
        }
        
        clients.erase(it);
    }
}

std::string VPNServer::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    return ss.str();
}

int VPNServer::getClientCount() const {
    std::lock_guard<std::mutex> lock(clientsMutex);
    return clients.size();
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
                    if (addr != "127.0.0.1") {
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
    std::vector<ClientInfo> result;
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    for (const auto& pair : clients) {
        result.push_back(pair.second);
    }
    
    return result;
}

bool VPNServer::disconnectClient(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        if (it->second.socket != INVALID_SOCKET) {
            close(it->second.socket);
            it->second.socket = INVALID_SOCKET;
        }
        
        if (it->second.ipAssigned) {
            ipPool.releaseIP(it->second.assignedVpnIP);
        }
        
        clients.erase(it);
        return true;
    }
    return false;
}

std::vector<std::string> VPNServer::getVPNStats() {
    std::vector<std::string> stats;
    stats.push_back("Available IPs: " + std::to_string(ipPool.getAvailableCount()));
    
    auto assignedIPs = ipPool.getAllAssignedIPs();
    stats.push_back("Assigned IPs: " + std::to_string(assignedIPs.size()));
    
    return stats;
}