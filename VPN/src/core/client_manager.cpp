#include "client_manager.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include "packet_handler.h"   
#ifdef _WIN32
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif

// IP Pool implementation
IPPool::IPPool(const std::string& network, int startRange, int endRange) 
    : baseNetwork(network) {
    for (int i = startRange; i <= endRange; i++) {
        std::string ip = baseNetwork + "." + std::to_string(i);
        availableIPs.push(ip);
        ipUsage[ip] = false;
    }
    std::cout << "[IP_POOL] Initialized: " << baseNetwork << "." << startRange << "-" << endRange 
              << " (" << (endRange - startRange + 1) << " IPs)\n";
}

std::string IPPool::assignIP() {
    std::lock_guard<std::mutex> lock(poolMutex);
    if (availableIPs.empty()) {
        std::cout << "[ERROR] No more IPs available in pool\n";
        return ""; 
    }
    
    std::string assignedIP = availableIPs.front();
    availableIPs.pop();
    ipUsage[assignedIP] = true;
    
    std::cout << "[IP_POOL] Assigned IP: " << assignedIP << " (Remaining: " << availableIPs.size() << ")\n";
    return assignedIP;
}

void IPPool::releaseIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(poolMutex);
    auto it = ipUsage.find(ip);
    if (it != ipUsage.end() && it->second) {
        it->second = false;
        availableIPs.push(ip);
        std::cout << "[IP_POOL] Released IP: " << ip << " (Available: " << availableIPs.size() << ")\n";
    }
}

int IPPool::getAvailableCount() {
    std::lock_guard<std::mutex> lock(poolMutex);
    return availableIPs.size();
}

std::vector<std::string> IPPool::getAllAssignedIPs() const {
    std::lock_guard<std::mutex> lock(poolMutex);
    std::vector<std::string> assigned;
    for (const auto& pair : ipUsage) {
        if (pair.second) {
            assigned.push_back(pair.first);
        }
    }
    return assigned;
}

// Client Manager implementation
ClientManager::ClientManager() : nextClientId(1), packetHandler(nullptr) {
    ipPool = new IPPool("10.8.0", 2, 254); // IP range 10.8.0.2 - 10.8.0.254
}

ClientManager::~ClientManager() {
    cleanup();
    if (ipPool) {
        delete ipPool;
        ipPool = nullptr;
    }
}

void ClientManager::setPacketHandler(PacketHandler* handler) {
    packetHandler = handler;
}

int ClientManager::addClient(SOCKET socket, const std::string& realIP, int port) {
    ClientInfo clientInfo;
    clientInfo.id = nextClientId++;
    clientInfo.socket = socket;
    clientInfo.realIP = realIP;
    clientInfo.port = port;
    clientInfo.connectTime = getCurrentTime();
    clientInfo.connectedAt = std::chrono::steady_clock::now();
    clientInfo.authenticated = false;
    clientInfo.ipAssigned = false;
    clientInfo.bytesSent = 0;
    clientInfo.bytesReceived = 0;
    
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients[clientInfo.id] = clientInfo;
    }
    
    std::cout << "[CLIENT_MGR] New client added - ID: " << clientInfo.id 
              << ", Real IP: " << realIP << ":" << port << "\n";
    
    return clientInfo.id;
}

bool ClientManager::authenticateClient(int clientId, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it == clients.end()) return false;
    
    // Simple authentication - accept any non-empty credentials
    // In production, implement proper authentication (database, LDAP, etc.)
    bool authenticated = !username.empty() && !password.empty();
    
    if (authenticated) {
        it->second.authenticated = true;
        it->second.username = username;
        
        std::cout << "[CLIENT_MGR] Client " << clientId << " (" << username << ") authenticated\n";
    } else {
        std::cout << "[CLIENT_MGR] Authentication failed for client " << clientId << "\n";
    }
    
    return authenticated;
}

bool ClientManager::assignVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it == clients.end() || !it->second.authenticated) return false;
    
    std::string assignedIP = ipPool->assignIP();
    if (assignedIP.empty()) {
        return false;
    }
    
    it->second.assignedVpnIP = assignedIP;
    it->second.ipAssigned = true;
    
    std::cout << "[CLIENT_MGR] Assigned VPN IP " << assignedIP << " to client " << clientId << "\n";
    return true;
}

void ClientManager::releaseVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.ipAssigned) {
        ipPool->releaseIP(it->second.assignedVpnIP);
        std::cout << "[CLIENT_MGR] Released VPN IP " << it->second.assignedVpnIP 
                  << " from client " << clientId << "\n";
        it->second.ipAssigned = false;
        it->second.assignedVpnIP.clear();
    }
}

std::string ClientManager::getClientVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.ipAssigned) {
        return it->second.assignedVpnIP;
    }
    return "";
}

int ClientManager::findClientByVPNIP(const std::string& vpnIP) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (const auto& pair : clients) {
        if (pair.second.authenticated && pair.second.ipAssigned && 
            pair.second.assignedVpnIP == vpnIP) {
            return pair.first;
        }
    }
    return -1;
}

bool ClientManager::sendToClient(int clientId, const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.socket != INVALID_SOCKET) {
        ssize_t sent = send(it->second.socket, message.c_str(), message.length(), MSG_NOSIGNAL);
        if (sent > 0) {
            return true;
        } else {
            std::cout << "[ERROR] Failed to send message to client " << clientId 
                      << ": " << strerror(errno) << "\n";
        }
    }
    return false;
}

void ClientManager::broadcastToClients(const std::string& message) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& pair : clients) {
        if (pair.second.socket != INVALID_SOCKET && pair.second.authenticated) {
            send(pair.second.socket, message.c_str(), message.length(), MSG_NOSIGNAL);
        }
    }
}

void ClientManager::handleClientPacket(int clientId, const char* packet, int size) {
    if (!packetHandler) {
        std::cout << "[ERROR] No packet handler available\n";
        return;
    }
    
    // Cập nhật thống kê client
    updateClientStats(clientId, 0, size); // bytes received from client
    
    // Chuyển packet cho packet handler xử lý
    packetHandler->handleClientPacket(clientId, packet, size);
}

bool ClientManager::removeClient(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        if (it->second.socket != INVALID_SOCKET) {
            close(it->second.socket);
        }
        
        if (it->second.ipAssigned) {
            ipPool->releaseIP(it->second.assignedVpnIP);
            std::cout << "[CLIENT_MGR] Released VPN IP: " << it->second.assignedVpnIP << "\n";
        }
        
        std::cout << "[CLIENT_MGR] Removed client " << clientId << "\n";
        clients.erase(it);
        return true;
    }
    return false;
}

bool ClientManager::disconnectClient(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        if (it->second.socket != INVALID_SOCKET) {
            sendToClient(clientId, "DISCONNECT|Server requested disconnect\n");
            close(it->second.socket);
            it->second.socket = INVALID_SOCKET;
        }
        
        if (it->second.ipAssigned) {
            ipPool->releaseIP(it->second.assignedVpnIP);
        }
        
        clients.erase(it);
        std::cout << "[CLIENT_MGR] Disconnected client " << clientId << "\n";
        return true;
    }
    return false;
}

void ClientManager::updateClientStats(int clientId, long long bytesSent, long long bytesReceived) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        it->second.bytesSent += bytesSent;
        it->second.bytesReceived += bytesReceived;
    }
}

std::vector<ClientInfo> ClientManager::getConnectedClients() const {
    std::vector<ClientInfo> result;
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    for (const auto& pair : clients) {
        result.push_back(pair.second);
    }
    
    return result;
}

int ClientManager::getClientCount() const {
    std::lock_guard<std::mutex> lock(clientsMutex);
    return clients.size();
}

std::vector<std::string> ClientManager::getAllAssignedVPNIPs() const {
    return ipPool->getAllAssignedIPs();
}

int ClientManager::getAvailableIPs() const {
    return ipPool->getAvailableCount();
}

ClientInfo* ClientManager::getClientInfo(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        return &it->second;
    }
    return nullptr;
}

bool ClientManager::isClientAuthenticated(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    return (it != clients.end() && it->second.authenticated);
}

bool ClientManager::hasVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    return (it != clients.end() && it->second.ipAssigned);
}

void ClientManager::cleanup() {
    std::cout << "[CLIENT_MGR] Cleaning up clients...\n";
    
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& pair : clients) {
        if (pair.second.socket != INVALID_SOCKET) {
            close(pair.second.socket);
        }
        
        if (pair.second.ipAssigned) {
            ipPool->releaseIP(pair.second.assignedVpnIP);
        }
    }
    clients.clear();
    
    std::cout << "[CLIENT_MGR] All clients cleaned up\n";
}

std::string ClientManager::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    return ss.str();
}

std::vector<std::string> ClientManager::getClientStats() {
    std::vector<std::string> stats;
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    stats.push_back("Client Manager Statistics:");
    stats.push_back("=========================");
    stats.push_back("Total Clients: " + std::to_string(clients.size()));
    stats.push_back("Available IPs: " + std::to_string(ipPool->getAvailableCount()));
    
    int authenticatedClients = 0;
    int assignedIPs = 0;
    
    for (const auto& pair : clients) {
        if (pair.second.authenticated) authenticatedClients++;
        if (pair.second.ipAssigned) assignedIPs++;
    }
    
    stats.push_back("Authenticated Clients: " + std::to_string(authenticatedClients));
    stats.push_back("Assigned VPN IPs: " + std::to_string(assignedIPs));
    
    return stats;
}

void ClientManager::disconnectAllClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (auto& pair : clients) {
        if (pair.second.socket != INVALID_SOCKET) {
            close(pair.second.socket);
            pair.second.socket = INVALID_SOCKET;
        }
        if (pair.second.ipAssigned) {
            releaseVPNIP(pair.first);
        }
    }
    clients.clear();
    std::cout << "[CLIENT_MGR] All clients disconnected\n";
}

SOCKET ClientManager::getClientSocket(int clientId) const {
    auto it = clients.find(clientId);
    if (it != clients.end()) {
        return it->second.socket;
    }
    return INVALID_SOCKET; 
}
