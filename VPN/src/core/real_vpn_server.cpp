// // real_vpn_server.cpp - Fixed implementation
// #include "real_vpn_server.h"
// #include "network/tun_interface.h"
// #include "base64.h"
// #include <iostream>
// #include <sstream>
// #include <arpa/inet.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <unistd.h>
// #include <sys/select.h>

// RealVPNServer::RealVPNServer(int port) 
//     : VPNServer(port), tun(nullptr), packetForwardingRunning(false) {
//     tun = new TUNInterface("vpn_server");
// }

// RealVPNServer::~RealVPNServer() {
//     stopPacketForwarding();
//     if (tun) {
//         delete tun;
//         tun = nullptr;
//     }
// }

// void RealVPNServer::handleClient(int clientId) {
//     ClientInfo* client = nullptr;
    
//     {
//         std::lock_guard<std::mutex> lock(getClientsMutex());
//         auto& clientsMap = getClientsMap();
//         auto it = clientsMap.find(clientId);
//         if (it != clientsMap.end()) {
//             client = &it->second;
            
//             // Create enhanced client info
//             EnhancedClientInfo enhancedInfo;
//             enhancedInfo.socket = client->socket;
//             enhancedInfo.address = client->ip + ":" + std::to_string(client->port);
//             enhancedInfo.authenticated = client->authenticated;
//             enhancedInfo.username = client->username;
//             enhancedInfo.ipAssigned = client->ipAssigned;
//             enhancedInfo.assignedVpnIP = client->assignedVpnIP;
//             enhancedInfo.connectionTime = client->connectedAt;
            
//             // {
//             //     std::lock_guard<std::mutex> packetLock(packetMutex);
//             //     enhancedClients.emplace(clientId, std::move(enhancedInfo));
//             // }
//             {
//                 std::lock_guard<std::mutex> packetLock(packetMutex);
//                 enhancedClients.emplace(std::make_pair(clientId, std::move(enhancedInfo)));
//             }
//         }
//     }

//     if (!client) return;

//     char buffer[4096];
    
//     std::string welcomeMsg = "WELCOME|Real VPN Server 2.0|Ready for authentication\n";
//     send(client->socket, welcomeMsg.c_str(), welcomeMsg.length(), 0);

//     while (!getShouldStop() && client->socket != INVALID_SOCKET) {
//         fd_set readfds;
//         FD_ZERO(&readfds);
//         FD_SET(client->socket, &readfds);
        
//         struct timeval timeout;
//         timeout.tv_sec = 1;
//         timeout.tv_usec = 0;
        
//         int ready = select(client->socket + 1, &readfds, nullptr, nullptr, &timeout);
        
//         if (ready <= 0) continue; // Timeout or error
        
//         if (!FD_ISSET(client->socket, &readfds)) continue;
        
//         int bytesReceived = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
        
//         if (bytesReceived <= 0) {
//             break; // Client disconnected
//         }

//         buffer[bytesReceived] = '\0';
//         std::string message(buffer);
        
//         // Handle multiple messages in one buffer
//         std::istringstream messageStream(message);
//         std::string line;
        
//         while (std::getline(messageStream, line)) {
//             if (line.empty()) continue;
            
//             // Remove carriage return if present
//             if (!line.empty() && line.back() == '\r') {
//                 line.pop_back();
//             }
            
//             std::istringstream iss(line);
//             std::string command;
//             iss >> command;

//             if (command == "AUTH") {
//                 std::string username, password;
//                 iss >> username >> password;
                
//                 if (authenticateClient(clientId, username, password)) {
//                     {
//                         std::lock_guard<std::mutex> lock(getClientsMutex());
//                         auto& clientsMap = getClientsMap();
//                         auto it = clientsMap.find(clientId);
//                         if (it != clientsMap.end()) {
//                             it->second.authenticated = true;
//                             it->second.username = username;
//                         }
//                     }
                    
//                     if (assignVPNIP(clientId)) {
//                         {
//                             std::lock_guard<std::mutex> lock(getClientsMutex());
//                             auto& clientsMap = getClientsMap();
//                             auto it = clientsMap.find(clientId);
//                             if (it != clientsMap.end()) {
//                                 client = &it->second; // Update pointer
//                             }
//                         }
                        
//                         std::string response = "AUTH_OK|Authentication successful|VPN_IP:" + client->assignedVpnIP + "\n";
//                         sendToClient(clientId, response);
//                         std::cout << "[INFO] Client " << clientId << " authenticated, assigned VPN IP: " 
//                                   << client->assignedVpnIP << std::endl;
                        
//                         // Start packet forwarding if not started
//                         if (!packetForwardingRunning) {
//                             startPacketForwarding();
//                         }
//                     } else {
//                         sendToClient(clientId, "AUTH_FAIL|No VPN IP available\n");
//                     }
//                 } else {
//                     sendToClient(clientId, "AUTH_FAIL|Invalid credentials\n");
//                 }
//             } 
//             else if (command == "PING") {
//                 sendToClient(clientId, "PONG\n");
//             } 
//             else if (command == "DATA" && client->authenticated) {
//                 // Handle packet data from client (base64 encoded)
//                 std::string packetDataB64;
//                 std::getline(iss, packetDataB64);
//                 if (!packetDataB64.empty() && packetDataB64[0] == '|') {
//                     packetDataB64 = packetDataB64.substr(1); // Remove |
//                 }
                
//                 try {
//                     // Decode base64
//                     std::vector<uint8_t> packet = base64_decode(packetDataB64);
                    
//                     if (!packet.empty()) {
//                         updateClientStats(clientId, packet.size(), false);
                        
//                         // Forward to TUN for routing
//                         forwardPacket(clientId, packet);
                        
//                         std::cout << "[PACKET] Received " << packet.size() << " bytes from client " 
//                                   << clientId << std::endl;
//                     }
//                 } catch (const std::exception& e) {
//                     std::cout << "[ERROR] Failed to decode packet data: " << e.what() << std::endl;
//                 }
//             } 
//             else if (command == "GET_STATS" && client->authenticated) {
//                 PacketStats stats = getClientStats(clientId);
//                 std::string response = "STATS|RX:" + std::to_string(stats.bytesReceived) + 
//                                        "|TX:" + std::to_string(stats.bytesSent) + 
//                                        "|PKT_RX:" + std::to_string(stats.packetsReceived) + 
//                                        "|PKT_TX:" + std::to_string(stats.packetsSent) + "\n";
//                 sendToClient(clientId, response);
//             } 
//             else if (command == "DISCONNECT") {
//                 sendToClient(clientId, "BYE|Goodbye\n");
//                 goto cleanup_client; // Break out of nested loops
//             } 
//             else if (client->authenticated) {
//                 if (command == "STATUS") {
//                     PacketStats stats = getClientStats(clientId);
//                     std::string status = "STATUS|Connected|VPN_IP:" + client->assignedVpnIP + 
//                                          "|RX:" + std::to_string(stats.bytesReceived) + 
//                                          "|TX:" + std::to_string(stats.bytesSent) + "\n";
//                     sendToClient(clientId, status);
//                 }
//             } 
//             else {
//                 sendToClient(clientId, "ERROR|Please authenticate first\n");
//             }
//         }
//     }

// cleanup_client:
//     std::cout << "[INFO] Client " << clientId << " disconnected" << std::endl;
//     removeClient(clientId);
// }

// void RealVPNServer::removeClient(int clientId) {
//     {
//         std::lock_guard<std::mutex> lock(packetMutex);
//         enhancedClients.erase(clientId);
//     }
    
//     VPNServer::removeClient(clientId);
    
//     // Stop packet forwarding if no clients
//     {
//         std::lock_guard<std::mutex> lock(packetMutex);
//         if (enhancedClients.empty() && packetForwardingRunning) {
//             stopPacketForwarding();
//         }
//     }
// }

// void RealVPNServer::startPacketForwarding() {
//     if (!packetForwardingRunning) {
//         // Create and configure TUN on server
//         if (!tun->create()) {
//             std::cout << "[ERROR] Failed to create TUN interface - requires root privileges" << std::endl;
//             return;
//         }
        
//         if (!tun->configure("10.8.0.1", "24", "", true)) {
//             std::cout << "[ERROR] Failed to configure TUN interface" << std::endl;
//             tun->close();
//             return;
//         }
        
//         packetForwardingRunning = true;
//         packetForwardingThread = std::thread([this]() { processPacketForwarding(); });
//         tunReadThread = std::thread([this]() { readFromTUN(); });
        
//         std::cout << "[INFO] Packet forwarding and TUN started (Server IP: 10.8.0.1/24)" << std::endl;
//     }
// }

// void RealVPNServer::stopPacketForwarding() {
//     if (packetForwardingRunning) {
//         packetForwardingRunning = false;
//         packetCV.notify_all();
        
//         if (packetForwardingThread.joinable()) {
//             packetForwardingThread.join();
//         }
//         if (tunReadThread.joinable()) {
//             tunReadThread.join();
//         }
        
//         if (tun) {
//             tun->close();
//         }
//         std::cout << "[INFO] Packet forwarding and TUN stopped" << std::endl;
//     }
// }

// void RealVPNServer::processPacketForwarding() {
//     while (packetForwardingRunning) {
//         std::unique_lock<std::mutex> lock(packetMutex);
        
//         bool hasWork = false;
        
//         for (auto& pair : enhancedClients) {
//             int clientId = pair.first;
//             EnhancedClientInfo& clientInfo = pair.second;
            
//             std::lock_guard<std::mutex> queueLock(clientInfo.packetQueueMutex);
            
//             while (!clientInfo.packetQueue.empty()) {
//                 std::vector<uint8_t> packet = clientInfo.packetQueue.front();
//                 clientInfo.packetQueue.pop();
                
//                 // Write packet to TUN for kernel routing
//                 if (tun && tun->isCreated()) {
//                     int written = tun->writePacket(reinterpret_cast<const char*>(packet.data()), packet.size());
//                     if (written > 0) {
//                         std::cout << "[TUN] Wrote " << written << " bytes to TUN interface" << std::endl;
//                         hasWork = true;
//                     }
//                 }
//             }
//         }
        
//         if (!hasWork) {
//             packetCV.wait_for(lock, std::chrono::milliseconds(100));
//         }
//     }
// }

// void RealVPNServer::readFromTUN() {
//     char buffer[2048];
//     while (packetForwardingRunning) {
//         if (!tun || !tun->isCreated()) {
//             std::this_thread::sleep_for(std::chrono::milliseconds(100));
//             continue;
//         }
        
//         int len = tun->readPacket(buffer, sizeof(buffer));
//         if (len > 0) {
//             std::vector<uint8_t> packet(buffer, buffer + len);
            
//             // Extract dest IP from IP header
//             std::string destIP = getDestinationIP(packet);
            
//             std::cout << "[TUN] Read " << len << " bytes, dest IP: " << destIP << std::endl;
            
//             // Find client by VPN IP
//             int targetClientId = findClientByVpnIP(destIP);
            
//             if (targetClientId != -1) {
//                 // Encode and send to client
//                 std::string dataB64 = base64_encode(packet);
//                 std::string dataMsg = "DATA|" + dataB64 + "\n";
//                 sendToClient(targetClientId, dataMsg);
//                 updateClientStats(targetClientId, len, true);
                
//                 std::cout << "[ROUTE] Forwarded " << len << " bytes to client " << targetClientId << std::endl;
//             } else {
//                 std::cout << "[ROUTE] External packet to " << destIP << " - handled by kernel routing" << std::endl;
//             }
//         } else if (len < 0) {
//             // Error reading from TUN
//             std::this_thread::sleep_for(std::chrono::milliseconds(10));
//         }
//     }
// }

// void RealVPNServer::forwardPacket(int fromClientId, const std::vector<uint8_t>& packet) {
//     std::lock_guard<std::mutex> lock(packetMutex);
    
//     auto it = enhancedClients.find(fromClientId);
//     if (it != enhancedClients.end()) {
//         std::lock_guard<std::mutex> queueLock(it->second.packetQueueMutex);
//         it->second.packetQueue.push(packet);
//         packetCV.notify_one();
//     }
// }

// std::string RealVPNServer::getDestinationIP(const std::vector<uint8_t>& packet) {
//     if (packet.size() < 20) return "";
    
//     // IP header: destination IP is at offset 16-19 (big-endian)
//     uint32_t destIP = *reinterpret_cast<const uint32_t*>(&packet[16]);
//     struct in_addr addr;
//     addr.s_addr = destIP;
//     return std::string(inet_ntoa(addr));
// }

// int RealVPNServer::findClientByVpnIP(const std::string& vpnIP) {
//     std::lock_guard<std::mutex> lock(getClientsMutex());
//     auto& clientsMap = getClientsMap();
//     for (const auto& pair : clientsMap) {
//         if (pair.second.ipAssigned && pair.second.assignedVpnIP == vpnIP) {
//             return pair.first;
//         }
//     }
//     return -1;
// }

// PacketStats RealVPNServer::getClientStats(int clientId) {
//     std::lock_guard<std::mutex> lock(packetMutex);
//     auto it = enhancedClients.find(clientId);
//     if (it != enhancedClients.end()) {
//         return it->second.stats;
//     }
//     return PacketStats();
// }

// void RealVPNServer::updateClientStats(int clientId, size_t bytes, bool sent) {
//     std::lock_guard<std::mutex> lock(packetMutex);
//     auto it = enhancedClients.find(clientId);
//     if (it != enhancedClients.end()) {
//         PacketStats& stats = it->second.stats;
//         if (sent) {
//             stats.bytesSent += bytes;
//             stats.packetsSent++;
//         } else {
//             stats.bytesReceived += bytes;
//             stats.packetsReceived++;
//         }
//         stats.lastActivity = std::chrono::steady_clock::now();
//     }
// }

// std::vector<std::pair<int, PacketStats>> RealVPNServer::getAllClientStats() {
//     std::vector<std::pair<int, PacketStats>> result;
//     std::lock_guard<std::mutex> lock(packetMutex);
//     for (const auto& pair : enhancedClients) {
//         result.push_back({pair.first, pair.second.stats});
//     }
//     return result;
// }

// std::string RealVPNServer::base64_encode(const std::vector<uint8_t>& data) {
//     return ::base64_encode(data.data(), data.size());
// }

// std::vector<uint8_t> RealVPNServer::base64_decode(const std::string& encoded) {
//     return ::base64_decode(encoded);
// }