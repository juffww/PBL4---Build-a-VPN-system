RealVPNServer::RealVPNServer(int port) : VPNServer(port), packetForwardingRunning(false)
{
}

RealVPNServer::~RealVPNServer()
{
    stopPacketForwarding();
}

void RealVPNServer::handleClient(int clientId)
{
    ClientInfo* client = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        auto it = clients.find(clientId);
        if (it != clients.end()) {
            client = &it->second;
            
            // Tạo enhanced client info
            EnhancedClientInfo enhancedInfo;
            static_cast<ClientInfo&>(enhancedInfo) = *client;
            enhancedClients[clientId] = std::move(enhancedInfo);
        }
    }

    if (!client) return;

    char buffer[4096];  // Tăng buffer size cho packet data
    
    std::string welcomeMsg = "WELCOME|Real VPN Server 1.0.0|Ready for authentication\n";
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
                              << client->assignedVpnIP << std::endl;
                    
                    // Start packet forwarding if not already started
                    if (!packetForwardingRunning) {
                        startPacketForwarding();
                    }
                } else {
                    sendToClient(clientId, "AUTH_FAIL|No VPN IP available\n");
                }
            } else {
                sendToClient(clientId, "AUTH_FAIL|Invalid credentials\n");
            }
        }
        else if (command == "PING") {
            sendToClient(clientId, "PONG\n");
        }
        else if (command == "DATA" && client->authenticated) {
            // Xử lý packet data từ client
            std::string packetDataB64;
            std::getline(iss, packetDataB64);
            
            if (packetDataB64.size() > 1) {
                packetDataB64 = packetDataB64.substr(1); // Remove leading |
                
                // Decode base64 packet
                QByteArray packetData = QByteArray::fromBase64(packetDataB64.c_str());
                std::vector<uint8_t> packet(packetData.begin(), packetData.end());
                
                if (!packet.empty()) {
                    // Update stats
                    updateClientStats(clientId, packet.size(), false);
                    
                    // Forward packet
                    forwardPacket(clientId, packet);
                    
                    std::cout << "[PACKET] Received " << packet.size() << " bytes from client " 
                              << clientId << std::endl;
                }
            }
        }
        else if (command == "GET_STATS" && client->authenticated) {
            PacketStats stats = getClientStats(clientId);
            std::string response = QString("STATS|RX:%1|TX:%2|PKT_RX:%3|PKT_TX:%4\n")
                .arg(stats.bytesReceived)
                .arg(stats.bytesSent) 
                .arg(stats.packetsReceived)
                .arg(stats.packetsSent).toStdString();
            sendToClient(clientId, response);
        }
        else if (command == "DISCONNECT") {
            sendToClient(clientId, "BYE|Goodbye\n");
            break;
        }
        else if (client->authenticated) {
            // Handle other authenticated commands
            if (command == "STATUS") {
                PacketStats stats = getClientStats(clientId);
                std::string status = QString("STATUS|Connected|VPN_IP:%1|RX:%2|TX:%3\n")
                    .arg(client->assignedVpnIP.c_str())
                    .arg(stats.bytesReceived)
                    .arg(stats.bytesSent).toStdString();
                sendToClient(clientId, status);
            }
        }
        else {
            sendToClient(clientId, "ERROR|Please authenticate first\n");
        }
    }

    std::cout << "[INFO] Client " << clientId << " disconnected" << std::endl;
    removeClient(clientId);
}

void RealVPNServer::removeClient(int clientId)
{
    // Remove from enhanced clients map
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        enhancedClients.erase(clientId);
    }
    
    // Call base class method
    VPNServer::removeClient(clientId);
    
    // Stop packet forwarding if no clients
    if (enhancedClients.empty() && packetForwardingRunning) {
        stopPacketForwarding();
    }
}

void RealVPNServer::startPacketForwarding()
{
    if (!packetForwardingRunning) {
        packetForwardingRunning = true;
        packetForwardingThread = std::thread([this]() { processPacketForwarding(); });
        std::cout << "[INFO] Packet forwarding started" << std::endl;
    }
}

void RealVPNServer::stopPacketForwarding()
{
    if (packetForwardingRunning) {
        packetForwardingRunning = false;
        packetCV.notify_all();
        
        if (packetForwardingThread.joinable()) {
            packetForwardingThread.join();
        }
        
        std::cout << "[INFO] Packet forwarding stopped" << std::endl;
    }
}

void RealVPNServer::processPacketForwarding()
{
    while (packetForwardingRunning) {
        std::unique_lock<std::mutex> lock(packetMutex);
        
        // Process queued packets from all clients
        bool hasWork = false;
        
        for (auto& pair : enhancedClients) {
            int clientId = pair.first;
            EnhancedClientInfo& clientInfo = pair.second;
            
            std::lock_guard<std::mutex> queueLock(clientInfo.packetQueueMutex);
            
            while (!clientInfo.packetQueue.empty()) {
                std::vector<uint8_t> packet = clientInfo.packetQueue.front();
                clientInfo.packetQueue.pop();
                
                // Route packet to destination
                routePacketToDestination(packet, clientId);
                hasWork = true;
            }
        }
        
        if (!hasWork) {
            // Wait for work or timeout
            packetCV.wait_for(lock, std::chrono::milliseconds(100));
        }
    }
}

void RealVPNServer::forwardPacket(int fromClientId, const std::vector<uint8_t>& packet)
{
    std::lock_guard<std::mutex> lock(packetMutex);
    
    auto it = enhancedClients.find(fromClientId);
    if (it != enhancedClients.end()) {
        std::lock_guard<std::mutex> queueLock(it->second.packetQueueMutex);
        it->second.packetQueue.push(packet);
        packetCV.notify_one();
    }
}

void RealVPNServer::routePacketToDestination(const std::vector<uint8_t>& packet, int sourceClientId)
{
    if (packet.size() < 20) return; // Minimum IP header size
    
    // Extract destination IP from IP header
    std::string destIP = getDestinationIP(packet);
    
    if (destIP.empty()) return;
    
    // Find target client by VPN IP
    int targetClientId = findClientByVpnIP(destIP);
    
    if (targetClientId != -1 && targetClientId != sourceClientId) {
        // Forward to target client
        std::lock_guard<std::mutex> lock(clientsMutex);
        auto it = clients.find(targetClientId);
        
        if (it != clients.end() && it->second.authenticated) {
            // Send packet to client as DATA message
            QByteArray packetData(reinterpret_cast<const char*>(packet.data()), packet.size());
            std::string dataMsg = "DATA|" + packetData.toBase64().toStdString() + "\n";
            
            sendToClient(targetClientId, dataMsg);
            updateClientStats(targetClientId, packet.size(), true);
            
            std::cout << "[ROUTE] Forwarded " << packet.size() << " bytes from client " 
                      << sourceClientId << " to client " << targetClientId << std::endl;
        }
    } else {
        // Route to external network (Internet)
        // This would require additional networking setup
        std::cout << "[ROUTE] External routing to " << destIP << " (not implemented)" << std::endl;
    }
}

std::string RealVPNServer::getDestinationIP(const std::vector<uint8_t>& packet)
{
    if (packet.size() < 20) return "";
    
    // Extract destination IP from IP header (bytes 16-19)
    uint32_t destIP = *reinterpret_cast<const uint32_t*>(&packet[16]);
    
    struct in_addr addr;
    addr.s_addr = destIP;
    
    return std::string(inet_ntoa(addr));
}

int RealVPNServer::findClientByVpnIP(const std::string& vpnIP)
{
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    for (const auto& pair : clients) {
        if (pair.second.ipAssigned && pair.second.assignedVpnIP == vpnIP) {
            return pair.first;
        }
    }
    
    return -1;
}

PacketStats RealVPNServer::getClientStats(int clientId)
{
    std::lock_guard<std::mutex> lock(packetMutex);
    
    auto it = enhancedClients.find(clientId);
    if (it != enhancedClients.end()) {
        return it->second.stats;
    }
    
    return PacketStats();
}

void RealVPNServer::updateClientStats(int clientId, size_t bytes, bool sent)
{
    std::lock_guard<std::mutex> lock(packetMutex);
    
    auto it = enhancedClients.find(clientId);
    if (it != enhancedClients.end()) {
        PacketStats& stats = it->second.stats;
        
        if (sent) {
            stats.bytesSent += bytes;
            stats.packetsSent++;
        } else {
            stats.bytesReceived += bytes;
            stats.packetsReceived++;
        }
        
        stats.lastActivity = std::chrono::steady_clock::now();
    }
}

std::vector<std::pair<int, PacketStats>> RealVPNServer::getAllClientStats()
{
    std::vector<std::pair<int, PacketStats>> result;
    std::lock_guard<std::mutex> lock(packetMutex);
    
    for (const auto& pair : enhancedClients) {
        result.push_back({pair.first, pair.second.stats});
    }
    
    return result;
}