#include "client_manager.h"
#include "packet_handler.h"
#include <iostream>
#include <openssl/err.h>
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
    cryptoBuffer.resize(65536);
    tagBuffer.resize(16);
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

bool ClientManager::authenticateClient(int clientId) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    auto it = clients.find(clientId);
    if (it == clients.end()) return false;
    
    it->second.authenticated = true;
    it->second.username = "anonymous"; 
    
    std::cout << "[SECURITY] Client " << clientId << " authenticated successfully (Anonymous)\n";
    return true;
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
    {
        std::lock_guard<std::mutex> lock(cryptoMutex);
        auto cryptoIt = cryptoMap.find(clientId);
        if (cryptoIt != cryptoMap.end()) {
            if (cryptoIt->second.encryptCtx) {
                EVP_CIPHER_CTX_free(cryptoIt->second.encryptCtx);
            }
            if (cryptoIt->second.decryptCtx) {
                EVP_CIPHER_CTX_free(cryptoIt->second.decryptCtx);
            }
            cryptoMap.erase(cryptoIt);
            std::cout << "[CRYPTO] Cleaned up contexts for client " << clientId << "\n";
        }
    }
    // --- KẾT THÚC PHẦN THÊM ---

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

    ClientCrypto& crypto = cryptoMap[clientId]; 

    crypto.udpSharedKey = key;
    // After setting crypto.udpSharedKey = key;
    uint8_t firstByte = key[0];
    uint8_t lastByte = key[31];
    std::cout << "[DEBUG] Client " << clientId << " Key Check: " 
              << std::hex << (int)firstByte << "..." << (int)lastByte << std::dec << "\n";

    crypto.ready = true;
    crypto.txCounter = 0;
    crypto.rxCounter = 0;
    crypto.rxWindowBitmap = 0;

    if (crypto.encryptCtx) EVP_CIPHER_CTX_free(crypto.encryptCtx);
    if (crypto.decryptCtx) EVP_CIPHER_CTX_free(crypto.decryptCtx);

    crypto.encryptCtx = EVP_CIPHER_CTX_new();
    crypto.decryptCtx = EVP_CIPHER_CTX_new();

    if (!crypto.encryptCtx || !crypto.decryptCtx) {
        std::cerr << "[CRYPTO] Failed to create EVP_CIPHER_CTX for client " << clientId << "\n";
        if (crypto.encryptCtx) EVP_CIPHER_CTX_free(crypto.encryptCtx);
        if (crypto.decryptCtx) EVP_CIPHER_CTX_free(crypto.decryptCtx);
        
        cryptoMap.erase(clientId);
        return false;
    }
        
    std::cout << "[CRYPTO] UDP encryption ready for client " << clientId << "\n";
    return true;
}

bool ClientManager::encryptPacket(int clientId, const char* plain, int plainSize,
                                  std::vector<uint8_t>& encrypted) {
    // std::lock_guard<std::mutex> mapLock(clientsMutex);
    std::lock_guard<std::mutex> mapLock(cryptoMutex); 
    auto it = cryptoMap.find(clientId);
    if (it == cryptoMap.end() || !it->second.ready || !it->second.encryptCtx) return false;
    
    ClientCrypto& crypto = it->second;
    std::lock_guard<std::mutex> clientLock(crypto.cryptoMutex);

    uint8_t iv[12]; 
    uint64_t counter = crypto.txCounter++;
    memcpy(iv, &counter, 8);
    memset(iv + 8, 0, 4);

    EVP_CIPHER_CTX* ctx = crypto.encryptCtx;
    const std::vector<uint8_t>& key = crypto.udpSharedKey;

    int max_size = 28 + plainSize + 16;
    if (encrypted.capacity() < max_size) {
        encrypted.reserve(max_size);
    }
    encrypted.resize(max_size);

    uint8_t* iv_ptr = encrypted.data();
    uint8_t* tag_ptr = encrypted.data() + 12;
    uint8_t* ciphertext_ptr = encrypted.data() + 28;

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) return false;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) return false;
    
    if (EVP_EncryptUpdate(ctx, ciphertext_ptr, &len, (const uint8_t*)plain, plainSize) != 1) return false;
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext_ptr + len, &len) != 1) return false;
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_ptr) != 1) return false;

    memcpy(iv_ptr, iv, 12);

    encrypted.resize(28 + ciphertext_len);
    
    return true;
}

bool ClientManager::decryptPacket(int clientId, const char* encrypted, int encSize,
                                  std::vector<uint8_t>& plain) {
    if (encSize < 28) return false;

    // std::lock_guard<std::mutex> mapLock(clientsMutex); 
    std::lock_guard<std::mutex> mapLock(cryptoMutex);
    auto it = cryptoMap.find(clientId);
    if (it == cryptoMap.end() || !it->second.ready || !it->second.decryptCtx) return false;

    ClientCrypto& crypto = it->second;
    std::lock_guard<std::mutex> clientLock(crypto.cryptoMutex);

    const uint8_t* iv_ptr = (const uint8_t*)encrypted;
    const uint8_t* tag_ptr = (const uint8_t*)encrypted + 12;
    const uint8_t* ciphertext_ptr = (const uint8_t*)encrypted + 28;
    int ciphertext_len = encSize - 28;

    uint64_t nonce = 0;
    memcpy(&nonce, iv_ptr, 8);

    if (nonce > crypto.rxCounter) {
        uint64_t diff = nonce - crypto.rxCounter;
        if (diff < 64) crypto.rxWindowBitmap <<= diff;
        else crypto.rxWindowBitmap = 0;
        crypto.rxWindowBitmap |= 1;
        crypto.rxCounter = nonce;
    } else {
        uint64_t diff = crypto.rxCounter - nonce;
        if (diff >= 64) return false; 
        uint64_t bit = 1ULL << diff;
        if ((crypto.rxWindowBitmap & bit) != 0) return false; 
        crypto.rxWindowBitmap |= bit;
    }

    if (plain.capacity() < ciphertext_len + 16) {
        plain.reserve(ciphertext_len + 16);
    }
    plain.resize(ciphertext_len + 16);

    EVP_CIPHER_CTX* ctx = crypto.decryptCtx;
    const std::vector<uint8_t>& key = crypto.udpSharedKey;
    
    int len = 0, plaintext_len = 0;

    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "[CRYPTO] Reset cipher failed\n";
        return false;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        std::cerr << "[CRYPTO] Set IV length failed\n";
        return false;
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr) != 1) {
        std::cerr << "[CRYPTO] Set key/IV failed\n";
        return false;
    }
    
    if (EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext_ptr, ciphertext_len) != 1) {
        std::cerr << "[CRYPTO] Decrypt Update failed\n";
        return false;
    }
    plaintext_len = len;
    
    // Set Tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag_ptr) != 1) {
        std::cerr << "[CRYPTO] Set TAG failed\n";
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plain.data() + len, &len);

    if (ret > 0) {
        plaintext_len += len;
        plain.resize(plaintext_len);
        return true;
    }
    
    std::cerr << "[CRYPTO] Decrypt Final failed (Bad Tag or Tampered)\n";
    ERR_print_errors_fp(stderr);
    
    return false;
}