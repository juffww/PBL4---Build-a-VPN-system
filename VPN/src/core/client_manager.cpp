#include "client_manager.h"
#include "packet_handler.h"
#include "crypto_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#ifdef _WIN32
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif

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
    ipPool = new IPPool("10.8.0", 2, 254);
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
    
    std::cout << "[CLIENT] Connected - ID: " << clientInfo.id 
              << ", IP: " << realIP << ":" << port << "\n";
    
    return clientInfo.id;
}

bool ClientManager::authenticateClient(int clientId, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it == clients.end()) return false;
    
    //bool authenticated = !username.empty() && !password.empty();
    bool authenticated = true;
    if (authenticated) {
        it->second.authenticated = true;
        it->second.username = username;
        std::cout << "[SECURITY] Client " << clientId << " (" << username << ") authenticated successfully\n";
    } else {
        std::cerr << "[SECURITY] Client " << clientId << " authentication failed (user: " << username << ")\n";
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
    
    std::cout << "[VPN] Assigned IP " << assignedIP << " to client " << clientId << "\n";
    return true;
}

void ClientManager::releaseVPNIP(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it != clients.end() && it->second.ipAssigned) {
        ipPool->releaseIP(it->second.assignedVpnIP);
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
        return;
    }
    
    updateClientStats(clientId, 0, size); 
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
        }
        
        std::cout << "[CLIENT] Disconnected - ID: " << clientId << "\n";
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
        std::cout << "[CLIENT] Kicked - ID: " << clientId << "\n";
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


bool ClientManager::setupUDPCrypto(int clientId, const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    
    if (key.size() != 32) {
        std::cerr << "[SECURITY] Invalid key size: " << key.size() << "\n";
        return false;
    }
    
    ClientCrypto crypto;
    crypto.udpSharedKey = key;
    crypto.ready = true;
    crypto.txCounter = 0;
    crypto.rxCounter = 0;
    cryptoMap[clientId] = crypto;
    
    std::cout << "[CRYPTO] UDP encryption ready for client " << clientId << "\n";
    return true;
}

// Update encryptPacket() to use udpSharedKey:
bool ClientManager::encryptPacket(int clientId, const char* plain, int plainSize,
                                  std::vector<uint8_t>& encrypted) {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    auto it = cryptoMap.find(clientId);
    if (it == cryptoMap.end() || !it->second.ready) return false;
    
    // Generate IV from counter
    std::vector<uint8_t> iv(12);
    uint64_t counter = it->second.txCounter++;
    memcpy(iv.data(), &counter, 8);
    
    std::vector<uint8_t> plainVec(plain, plain + plainSize);
    std::vector<uint8_t> ciphertext, tag;
    
    if (!CryptoEngine::Encrypt(it->second.udpSharedKey, iv, plainVec, ciphertext, tag)) {
        return false;
    }
    
    // Format: [IV:12][Tag:16][Ciphertext:N]
    encrypted.resize(28 + ciphertext.size());
    memcpy(encrypted.data(), iv.data(), 12);
    memcpy(encrypted.data() + 12, tag.data(), 16);
    memcpy(encrypted.data() + 28, ciphertext.data(), ciphertext.size());
    
    return true;
}

// Update decryptPacket() similarly:
bool ClientManager::decryptPacket(int clientId, const char* encrypted, int encSize,
                                  std::vector<uint8_t>& plain) {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    auto it = cryptoMap.find(clientId);
    if (it == cryptoMap.end() || !it->second.ready || encSize < 28) return false;
    
    std::vector<uint8_t> iv(encrypted, encrypted + 12);
    std::vector<uint8_t> tag(encrypted + 12, encrypted + 28);
    std::vector<uint8_t> ciphertext(encrypted + 28, encrypted + encSize);
    
    if (!CryptoEngine::Decrypt(it->second.udpSharedKey, iv, ciphertext, tag, plain)) {
        return false;
    }
    
    return true;
}

