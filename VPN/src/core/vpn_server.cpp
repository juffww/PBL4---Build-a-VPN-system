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

// IPPool Implementation
IPPool::IPPool(const std::string& network, int startRange, int endRange) 
    : baseNetwork(network) {
    // Tạo pool các IP từ 10.8.0.2 đến 10.8.0.254
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

std::vector<std::string> IPPool::getAllAssignedIPs() {
    std::lock_guard<std::mutex> lock(poolMutex);
    std::vector<std::string> assigned;
    
    for (const auto& pair : ipUsage) {
        if (pair.second) {
            assigned.push_back(pair.first);
        }
    }
    
    return assigned;
}

// VPNServer Implementation
VPNServer::VPNServer(int port) 
    : serverPort(port), serverSocket(INVALID_SOCKET), isRunning(false), 
      shouldStop(false), nextClientId(1) {
}

VPNServer::~VPNServer() {
    stop();
}

bool VPNServer::initialize() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] Không thể tạo socket\n";
        return false;
    }

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) < 0) {
        std::cout << "[WARN] Không thể set SO_REUSEADDR\n";
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(serverPort);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "[ERROR] Không thể bind socket trên cổng " << serverPort << "\n";
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }

    if (listen(serverSocket, 10) == SOCKET_ERROR) {
        std::cout << "[ERROR] Không thể listen trên socket\n";
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }

    return true;
}

void VPNServer::start() {
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "[ERROR] Server chưa được khởi tạo\n";
        return;
    }

    isRunning = true;
    shouldStop = false;
    startTime = std::chrono::steady_clock::now();
    
    std::cout << "[INFO] VPN Server đang lắng nghe kết nối...\n";
    std::cout << "[INFO] IP Pool: " << ipPool.getAvailableCount() << " IPs available\n";
    acceptConnections();
}

void VPNServer::stop() {
    shouldStop = true;
    isRunning = false;

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
            // Release VPN IP
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
}

void VPNServer::acceptConnections() {
    while (!shouldStop && isRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        
        if (clientSocket == INVALID_SOCKET) {
            if (!shouldStop) {
                std::cout << "[ERROR] Lỗi khi accept connection\n";
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
        clientInfo.realIP = clientInfo.ip; // Lưu IP thật
        clientInfo.ipAssigned = false;

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients[clientInfo.id] = clientInfo;
        }

        std::cout << "[INFO] Client mới kết nối - ID: " << clientInfo.id 
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

    char buffer[1024];
    
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
                
                // Cấp phát VPN IP
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
                std::cout << "[DEBUG] Data từ client " << clientId << ": " << message << "\n";
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
    // Xác thực đơn giản - chấp nhận mọi username/password không rỗng
    // Trong thực tế nên sử dụng database hoặc file cấu hình
    return !username.empty() && !password.empty();
}

bool VPNServer::assignVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it == clients.end()) return false;
    
    std::string assignedIP = ipPool.assignIP();
    if (assignedIP.empty()) {
        return false; // Hết IP
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
        
        // Release VPN IP
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
        
        // Release VPN IP
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