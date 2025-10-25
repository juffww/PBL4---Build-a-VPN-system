#include "vpn_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include <unordered_map> 
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
    #include <netinet/tcp.h> 
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


void VPNServer::handleUDPPackets() {
    char buffer[65536];
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; 
    setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    
    int rcvbuf = 2097152; 
    int sndbuf = 2097152; 

    setsockopt(udpSocket, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    setsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
    
    while (!shouldStop) {
        int n = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&clientAddr, &addrLen);
        
        if (n > 0) {
            if (n >= 8) {
                int clientId = *(int*)buffer;
                int dataSize = *(int*)(buffer + 4);
                
                if (clientId <= 0 || clientId > 1000) {
                    continue;
                }
                
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
                
                if (dataSize > 0 && dataSize <= (n - 8) && dataSize < 65536) {
                    std::lock_guard<std::mutex> lock(udpAddrMutex);
                    clientUDPAddrs[clientId] = clientAddr;
                    
                    std::vector<uint8_t> plainPacket;
                    if (clientManager->decryptPacket(clientId, buffer + 8, dataSize, plainPacket)) {
                        clientManager->handleClientPacket(clientId, 
                            (char*)plainPacket.data(), plainPacket.size());
                    } else {
                        static int decryptFailCount = 0;
                        if (++decryptFailCount % 100 == 0) {
                            std::cerr << "[SECURITY] Rejected " << decryptFailCount 
                                    << " tampered packets\n";
                        }
                    }
                }
            }
        }
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

// void VPNServer::handleClient(int clientId) {
//     ClientInfo* client = clientManager->getClientInfo(clientId);
//     if (!client) return;

//     int flag = 1;
//     setsockopt(client->socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

//     char buffer[4096];
//     std::string welcomeMsg = "WELCOME|VPN Server 2.0.0|Ready for authentication\n";
//     clientManager->sendToClient(clientId, welcomeMsg);

//     std::string messageBuffer;
//     bool expectingPacketData = false;
//     int packetSizeToRead = 0;
    
//     // Rate limiting trackers
//     static std::unordered_map<int, std::chrono::steady_clock::time_point> lastCryptoInit;
//     static std::unordered_map<int, int> cryptoAttempts;
//     static std::mutex rateLimitMutex;

//     while (!shouldStop && client->socket != INVALID_SOCKET) {
//         int bytesReceived = recv(client->socket, buffer, sizeof(buffer), 0);
//         if (bytesReceived <= 0) break;

//         messageBuffer.append(buffer, bytesReceived);
        
//         // ✅ Wait 10ms for more data (fix multiline commands)
//         std::this_thread::sleep_for(std::chrono::milliseconds(10));

//         // ✅ Buffer overflow protection
//         if (messageBuffer.size() > 65536) {
//             std::cerr << "[SECURITY] Client " << clientId << " buffer overflow detected\n";
//             break;
//         }

//         while(true) {
//             if (expectingPacketData) {
//                 if (messageBuffer.length() >= static_cast<size_t>(packetSizeToRead)){
//                     clientManager->handleClientPacket(clientId, messageBuffer.data(), packetSizeToRead);
//                     messageBuffer.erase(0, packetSizeToRead);
//                     expectingPacketData = false;
//                     packetSizeToRead = 0;
//                 } else {
//                     break;
//                 }
//             }
//             else {
//                 size_t newline = messageBuffer.find('\n');
//                 if (newline == std::string::npos) break;

//                 std::string line = messageBuffer.substr(0, newline);
//                 messageBuffer.erase(0, newline + 1);

//                 // AUTH command
//                 if (line.rfind("AUTH ", 0) == 0) {
//                     std::istringstream iss(line);
//                     std::string cmd, username, password;
//                     iss >> cmd >> username >> password;
                    
//                     if (!handleAuthCommand(clientId, iss)) break;
//                 }
//                 // ✅ FIX: CRYPTO_INIT with proper validation
//                 else if (line.rfind("CRYPTO_INIT|", 0) == 0) {
//                     // ✅ 1. CHECK AUTHENTICATION FIRST
//                     if (!clientManager->isClientAuthenticated(clientId)) {
//                         std::cerr << "[SECURITY] Unauthenticated CRYPTO_INIT from client " 
//                                   << clientId << "\n";
//                         clientManager->sendToClient(clientId, "ERROR|Not authenticated\n");
//                         continue;
//                     }
                    
//                     // ✅ 2. RATE LIMITING
//                     {
//                         std::lock_guard<std::mutex> lock(rateLimitMutex);
//                         auto now = std::chrono::steady_clock::now();
                        
//                         if (lastCryptoInit.count(clientId)) {
//                             auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
//                                 now - lastCryptoInit[clientId]).count();
                            
//                             if (elapsed < 1000) {
//                                 cryptoAttempts[clientId]++;
//                                 if (cryptoAttempts[clientId] > 3) {
//                                     std::cerr << "[SECURITY] Client " << clientId 
//                                              << " exceeded crypto rate limit\n";
//                                     clientManager->sendToClient(clientId, "ERROR|Rate limit\n");
//                                     continue;
//                                 }
//                             } else {
//                                 cryptoAttempts[clientId] = 0;
//                             }
//                         }
//                         lastCryptoInit[clientId] = now;
//                     }
                    
//                     // ✅ 3. PREVENT RE-INITIALIZATION
//                     std::string existingKey = clientManager->getServerPublicKey(clientId);
//                     if (!existingKey.empty()) {
//                         std::cerr << "[SECURITY] Client " << clientId 
//                                  << " attempted crypto re-init\n";
//                         clientManager->sendToClient(clientId, "ERROR|Already initialized\n");
//                         continue;
//                     }
                    
//                     // ✅ 4. PARSE KEY - CHỜ ĐỌC MULTI-LINE PEM
//                     std::string clientPubKey;
//                     size_t pos = line.find('|');
//                     if (pos != std::string::npos && pos + 1 < line.length()) {
//                         clientPubKey = line.substr(pos + 1);
                        
//                         // ✅ Đọc thêm các dòng PEM còn lại
//                         while (clientPubKey.find("END PUBLIC KEY") == std::string::npos) {
//                             if (messageBuffer.find('\n') == std::string::npos) {
//                                 // Chờ thêm data
//                                 break;
//                             }
//                             size_t nextNewline = messageBuffer.find('\n');
//                             std::string nextLine = messageBuffer.substr(0, nextNewline);
//                             messageBuffer.erase(0, nextNewline + 1);
                            
//                             clientPubKey += "\n" + nextLine;
                            
//                             // ✅ Buffer overflow protection
//                             if (clientPubKey.length() > 2048) {
//                                 std::cerr << "[SECURITY] PEM key too large\n";
//                                 clientManager->sendToClient(clientId, "CRYPTO_FAIL|Key too large\n");
//                                 goto cleanup;
//                             }
//                         }
                        
//                         if (clientPubKey.find("END PUBLIC KEY") == std::string::npos) {
//                             messageBuffer = "CRYPTO_INIT|" + clientPubKey + "\n" + messageBuffer;
//                             break;
//                         }
//                     } else {
//                         std::cerr << "[SECURITY] Client " << clientId << " invalid format\n";
//                         clientManager->sendToClient(clientId, "CRYPTO_FAIL|Invalid format\n");
//                         continue;
//                     }
                    
//                     // ✅ 5. VALIDATE KEY FORMAT
//                     if (clientPubKey.find("-----BEGIN PUBLIC KEY-----") == std::string::npos ||
//                         clientPubKey.find("-----END PUBLIC KEY-----") == std::string::npos) {
//                         std::cerr << "[SECURITY] Client " << clientId << " incomplete PEM\n";
//                         clientManager->sendToClient(clientId, "CRYPTO_FAIL|Invalid key\n");
//                         continue;
//                     }
                    
//                     // ✅ 6. SETUP CRYPTO
//                     if (clientManager->setupCrypto(clientId, clientPubKey)) {
//                         std::string serverPubKey = clientManager->getServerPublicKey(clientId);
                        
//                         // ✅ FIX: Send response IMMEDIATELY, không chờ
//                         std::string response = "CRYPTO_OK|" + serverPubKey + "\n";
//                         send(client->socket, response.c_str(), response.length(), MSG_NOSIGNAL);
                        
//                         std::cout << "[CRYPTO] ✓ Handshake complete with client " << clientId << "\n";
//                     } else {
//                         std::cerr << "[SECURITY] Client " << clientId << " crypto setup failed\n";
                        
//                         // ✅ FIX: Send error response IMMEDIATELY
//                         std::string errorMsg = "CRYPTO_FAIL|Setup failed\n";
//                         send(client->socket, errorMsg.c_str(), errorMsg.length(), MSG_NOSIGNAL);
//                     }
//                 }
//                 // Other commands
//                 else if (line.rfind("PING", 0) == 0) {
//                     handlePingCommand(clientId);
//                 }
//                 else if (line.rfind("GET_STATUS", 0) == 0) {
//                     handleStatusCommand(clientId);
//                 }
//                 else if (line.rfind("DISCONNECT", 0) == 0) {
//                     clientManager->sendToClient(clientId, "BYE|Goodbye\n");
//                     goto cleanup;
//                 }
//                 else if (line.rfind("DATA|", 0) == 0) {
//                     size_t pos = line.find('|');
//                     if (pos != std::string::npos) {
//                         std::string sizeStr = line.substr(pos + 1);
//                         try {
//                             packetSizeToRead = std::stoi(sizeStr);
//                             if (packetSizeToRead > 0 && packetSizeToRead <= 2048) {
//                                 expectingPacketData = true;
//                             } else {
//                                 std::cerr << "[SECURITY] Invalid packet size: " 
//                                          << packetSizeToRead << "\n";
//                             }
//                         } catch (...) {
//                             std::cerr << "[SECURITY] Invalid DATA command\n";
//                         }
//                     }
//                 }
//                 else {
//                     if (!clientManager->isClientAuthenticated(clientId)) {
//                         clientManager->sendToClient(clientId, "ERROR|Please authenticate first\n");
//                     } else {
//                         clientManager->sendToClient(clientId, "ERROR|Unknown command\n");
//                     }
//                 }
//             }
//         }
//     }

// cleanup:
//     clientManager->removeClient(clientId);
// }
// In handleClient(), fix the message buffer processing:

void VPNServer::handleClient(int clientId) {
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (!client) return;

    int flag = 1;
    setsockopt(client->socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    char buffer[4096];
    std::string welcomeMsg = "WELCOME|VPN Server 2.0.0|Ready for authentication\n";
    clientManager->sendToClient(clientId, welcomeMsg);

    std::string messageBuffer;
    bool expectingPacketData = false;
    int packetSizeToRead = 0;
    
    // Rate limiting trackers
    static std::unordered_map<int, std::chrono::steady_clock::time_point> lastCryptoInit;
    static std::unordered_map<int, int> cryptoAttempts;
    static std::mutex rateLimitMutex;

    std::cout << "[CLIENT] " << clientId << " connected from " 
              << client->realIP << ":" << client->port << "\n";  // ✅ ADD LOGGING

    while (!shouldStop && client->socket != INVALID_SOCKET) {
        int bytesReceived = recv(client->socket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            std::cout << "[CLIENT] " << clientId << " disconnected\n";  // ✅ ADD LOGGING
            break;
        }

        messageBuffer.append(buffer, bytesReceived);
        
        // ❌ REMOVE THIS - it slows down response and test timeout
        // std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // ✅ Buffer overflow protection
        if (messageBuffer.size() > 65536) {
            std::cerr << "[SECURITY] Client " << clientId << " buffer overflow detected\n";
            break;
        }

        while(true) {
            if (expectingPacketData) {
                if (messageBuffer.length() >= static_cast<size_t>(packetSizeToRead)){
                    clientManager->handleClientPacket(clientId, messageBuffer.data(), packetSizeToRead);
                    messageBuffer.erase(0, packetSizeToRead);
                    expectingPacketData = false;
                    packetSizeToRead = 0;
                } else {
                    break;
                }
            }
            else {
                size_t newline = messageBuffer.find('\n');
                if (newline == std::string::npos) break;

                std::string line = messageBuffer.substr(0, newline);
                messageBuffer.erase(0, newline + 1);

                // ✅ ADD LOGGING for all commands
                std::cout << "[CMD] Client " << clientId << ": " << line.substr(0, 50) 
                         << (line.length() > 50 ? "..." : "") << "\n";

                // AUTH command
                if (line.rfind("AUTH ", 0) == 0) {
                    std::istringstream iss(line);
                    std::string cmd, username, password;
                    iss >> cmd >> username >> password;
                    
                    if (!handleAuthCommand(clientId, iss)) break;
                }
                // ✅ CRYPTO_INIT with proper validation
                else if (line.rfind("CRYPTO_INIT|", 0) == 0) {
                    // ✅ 1. CHECK AUTHENTICATION FIRST
                    if (!clientManager->isClientAuthenticated(clientId)) {
                        std::cerr << "[SECURITY] Unauthenticated CRYPTO_INIT from client " 
                                  << clientId << "\n";
                        clientManager->sendToClient(clientId, "ERROR|Not authenticated\n");
                        continue;  // ✅ Don't break, just skip
                    }
                    
                    // ✅ 2. RATE LIMITING
                    {
                        std::lock_guard<std::mutex> lock(rateLimitMutex);
                        auto now = std::chrono::steady_clock::now();
                        
                        if (lastCryptoInit.count(clientId)) {
                            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - lastCryptoInit[clientId]).count();
                            
                            if (elapsed < 1000) {
                                cryptoAttempts[clientId]++;
                                if (cryptoAttempts[clientId] > 3) {
                                    std::cerr << "[SECURITY] Client " << clientId 
                                             << " exceeded crypto rate limit\n";
                                    clientManager->sendToClient(clientId, "ERROR|Rate limit\n");
                                    continue;  // ✅ Don't break
                                }
                            } else {
                                cryptoAttempts[clientId] = 0;
                            }
                        }
                        lastCryptoInit[clientId] = now;
                    }
                    
                    // ✅ 3. PREVENT RE-INITIALIZATION
                    std::string existingKey = clientManager->getServerPublicKey(clientId);
                    if (!existingKey.empty()) {
                        std::cerr << "[SECURITY] Client " << clientId 
                                 << " attempted crypto re-init\n";
                        clientManager->sendToClient(clientId, "ERROR|Already initialized\n");
                        continue;  // ✅ Don't break
                    }
                    
                    // ✅ 4. PARSE KEY - Wait for complete multi-line PEM
                    std::string clientPubKey;
                    size_t pos = line.find('|');
                    if (pos != std::string::npos && pos + 1 < line.length()) {
                        clientPubKey = line.substr(pos + 1);
                        
                        // ✅ Read remaining PEM lines
                        while (clientPubKey.find("END PUBLIC KEY") == std::string::npos) {
                            if (messageBuffer.find('\n') == std::string::npos) {
                                // Wait for more data
                                break;
                            }
                            size_t nextNewline = messageBuffer.find('\n');
                            std::string nextLine = messageBuffer.substr(0, nextNewline);
                            messageBuffer.erase(0, nextNewline + 1);
                            
                            clientPubKey += "\n" + nextLine;
                            
                            // ✅ Buffer overflow protection
                            if (clientPubKey.length() > 2048) {
                                std::cerr << "[SECURITY] PEM key too large\n";
                                clientManager->sendToClient(clientId, "CRYPTO_FAIL|Key too large\n");
                                goto next_command;  // ✅ Skip to next command
                            }
                        }
                        
                        if (clientPubKey.find("END PUBLIC KEY") == std::string::npos) {
                            // Put back incomplete command
                            messageBuffer = "CRYPTO_INIT|" + clientPubKey + "\n" + messageBuffer;
                            break;
                        }
                    } else {
                        std::cerr << "[SECURITY] Client " << clientId << " invalid format\n";
                        clientManager->sendToClient(clientId, "CRYPTO_FAIL|Invalid format\n");
                        continue;  // ✅ Don't break
                    }
                    
                    // ✅ 5. VALIDATE KEY FORMAT
                    if (clientPubKey.find("-----BEGIN PUBLIC KEY-----") == std::string::npos ||
                        clientPubKey.find("-----END PUBLIC KEY-----") == std::string::npos) {
                        std::cerr << "[SECURITY] Client " << clientId << " incomplete PEM\n";
                        clientManager->sendToClient(clientId, "CRYPTO_FAIL|Invalid key\n");
                        continue;  // ✅ Don't break
                    }
                    
                    // ✅ 6. SETUP CRYPTO
                    if (clientManager->setupCrypto(clientId, clientPubKey)) {
                        std::string serverPubKey = clientManager->getServerPublicKey(clientId);
                        std::string response = "CRYPTO_OK|" + serverPubKey + "\n";
                        send(client->socket, response.c_str(), response.length(), MSG_NOSIGNAL);
                        std::cout << "[CRYPTO] ✓ Handshake complete with client " << clientId << "\n";
                    } else {
                        std::cerr << "[SECURITY] Client " << clientId << " crypto setup failed\n";
                        std::string errorMsg = "CRYPTO_FAIL|Setup failed\n";
                        send(client->socket, errorMsg.c_str(), errorMsg.length(), MSG_NOSIGNAL);
                    }
                    
                    next_command:;  // ✅ Label for goto
                }
                // Other commands
                else if (line.rfind("PING", 0) == 0) {
                    handlePingCommand(clientId);
                }
                else if (line.rfind("GET_STATUS", 0) == 0) {
                    handleStatusCommand(clientId);
                }
                else if (line.rfind("DISCONNECT", 0) == 0) {
                    clientManager->sendToClient(clientId, "BYE|Goodbye\n");
                    goto cleanup;
                }
                else if (line.rfind("DATA|", 0) == 0) {
                    size_t pos = line.find('|');
                    if (pos != std::string::npos) {
                        std::string sizeStr = line.substr(pos + 1);
                        try {
                            packetSizeToRead = std::stoi(sizeStr);
                            if (packetSizeToRead > 0 && packetSizeToRead <= 2048) {
                                expectingPacketData = true;
                            } else {
                                std::cerr << "[SECURITY] Invalid packet size: " 
                                         << packetSizeToRead << "\n";
                            }
                        } catch (...) {
                            std::cerr << "[SECURITY] Invalid DATA command\n";
                        }
                    }
                }
                else {
                    if (!clientManager->isClientAuthenticated(clientId)) {
                        clientManager->sendToClient(clientId, "ERROR|Please authenticate first\n");
                    } else {
                        clientManager->sendToClient(clientId, "ERROR|Unknown command\n");
                    }
                }
            }
        }
    }

cleanup:
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