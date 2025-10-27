#include "vpn_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unordered_map> 
#include "client_manager.h" 
#include "tunnel_manager.h"
#include "packet_handler.h"
#ifdef _WIN32
    #include <ws2tcpip.h>
    
    #define close closesocket
    #define MSG_NOSIGNAL 0
#else
    #include <fcntl.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h> 
    #include <errno.h>
#endif

VPNServer::VPNServer(int port, const std::string& cert, const std::string& key) 
    : serverPort(port), certFile(cert), keyFile(key), serverSocket(INVALID_SOCKET), isRunning(false), 
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


void VPNServer::sendTLS(int clientId, const std::string& message) {
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (client && client->tlsWrapper) {
        int sent = client->tlsWrapper->send(message.c_str(), message.length());
        std::cout << "[DEBUG] sendTLS: " << sent << " bytes sent to client " << clientId << "\n";
    } else {
        std::cerr << "[ERROR] sendTLS: Invalid client or TLS wrapper\n";
    }
}


// void VPNServer::handleClient(int clientId) {
//     ClientInfo* client = clientManager->getClientInfo(clientId);
//     if (!client) return;

//     std::this_thread::sleep_for(std::chrono::milliseconds(100));

//     client->tlsWrapper = new TLSWrapper(true); 
    
//     if (!client->tlsWrapper->loadCertificates(certFile, keyFile)) {
//         std::cerr << "[TLS] Failed to load certificates for client " << clientId << "\n";
//         client->tlsWrapper->cleanup();
//         delete client->tlsWrapper;
//         client->tlsWrapper = nullptr;
//         clientManager->removeClient(clientId);
//         return;
//     }
    
//     std::cout << "[TLS] Starting handshake with client " << clientId 
//               << " (FD: " << client->socket << ")\n";
    
//     // ✅ CRITICAL: Set socket to blocking mode for handshake
//     #ifndef _WIN32
//     int flags = fcntl(client->socket, F_GETFL, 0);
//     fcntl(client->socket, F_SETFL, flags & ~O_NONBLOCK);
//     #endif
    
//     if (!client->tlsWrapper->initTLS(client->socket)) {
//         std::cerr << "[TLS] Handshake failed with client " << clientId << "\n";
//         goto cleanup;
//     }
    
//     std::cout << "[CLIENT] " << clientId << " TLS secured from " 
//               << client->realIP << ":" << client->port << "\n";

//     // Send welcome over TLS
//     {
//         std::string welcomeMsg = "WELCOME|VPN Server 2.0.0 TLS|Ready\n";
//         if (client->tlsWrapper->send(welcomeMsg.c_str(), welcomeMsg.length()) <= 0) {
//             std::cerr << "[TLS] Failed to send welcome message\n";
//             goto cleanup;
//         }
//     }

//     // Main loop - receive over TLS
//     {
//         char buffer[4096];
//         std::string messageBuffer;
        
//         while (!shouldStop && client->socket != INVALID_SOCKET) {
//             int bytesReceived = client->tlsWrapper->recv(buffer, sizeof(buffer));
            
//             if (bytesReceived <= 0) {
//                 int err = SSL_get_error(client->tlsWrapper->getSSL(), bytesReceived);
                
//                 if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
//                     std::this_thread::sleep_for(std::chrono::milliseconds(10));
//                     continue;
//                 }
                
//                 std::cout << "[CLIENT] " << clientId << " disconnected (SSL error: " << err << ")\n";
//                 break;
//             }

//             messageBuffer.append(buffer, bytesReceived);
            
//             if (messageBuffer.size() > 65536) {
//                 std::cerr << "[SECURITY] Buffer overflow detected\n";
//                 break;
//             }

//             size_t newline;
//             while ((newline = messageBuffer.find('\n')) != std::string::npos) {
//                 std::string line = messageBuffer.substr(0, newline);
//                 messageBuffer.erase(0, newline + 1);
                
//                 std::cout << "[CMD] Client " << clientId << ": " << line.substr(0, 50) << "\n";
                
//                 if (line.rfind("AUTH ", 0) == 0) {
//                     std::istringstream iss(line);
//                     std::string cmd, username, password;
//                     iss >> cmd >> username >> password;
                    
//                     if (!handleAuthCommand(clientId, iss)) break;
//                 }
//                 else if (line == "UDP_KEY_REQUEST") {
//                     if (!clientManager->isClientAuthenticated(clientId)) {
//                         sendTLS(clientId, "ERROR|Not authenticated\n");

//                         SSL_write(client->tlsWrapper->getSSL(), "", 0);
                        
//                         struct timeval tv;
//                         tv.tv_sec = 30;  
//                         tv.tv_usec = 0;
//                         setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, 
//                                 (const char*)&tv, sizeof(tv));
//                     }
                    
//                     std::vector<uint8_t> udpKey(32);
//                     if (RAND_bytes(udpKey.data(), 32) != 1) {
//                         sendTLS(clientId, "UDP_KEY_FAIL|Key generation failed\n");
//                         continue;
//                     }
                    
//                     if (!clientManager->setupUDPCrypto(clientId, udpKey)) {
//                         sendTLS(clientId, "UDP_KEY_FAIL|Setup failed\n");
//                         continue;
//                     }
                    
//                     std::string response = "UDP_KEY|";
//                     response.append((char*)udpKey.data(), 32);
//                     response += "\n";
                    
//                     if (client->tlsWrapper->send(response.c_str(), response.length()) <= 0) {
//                         std::cerr << "[TLS] Failed to send UDP key\n";
//                         break;
//                     }
//                     std::cout << "[CRYPTO] UDP key sent to client " << clientId << "\n";
//                 }
//                 else if (line == "PING") {
//                     handlePingCommand(clientId);
//                     SSL_write(client->tlsWrapper->getSSL(), "", 0);
//                 }
//                 else if (line == "GET_STATUS") {
//                     handleStatusCommand(clientId);
//                     SSL_write(client->tlsWrapper->getSSL(), "", 0);
//                 }
//                 else if (line == "DISCONNECT") {
//                     sendTLS(clientId, "BYE|Goodbye\n");
//                     goto cleanup;
//                 }
//                 else {
//                     sendTLS(clientId, "ERROR|Unknown command\n");
//                 }
//             }
//         }
//     }

// cleanup:
//     if (client->tlsWrapper) {
//         client->tlsWrapper->cleanup();
//         delete client->tlsWrapper;
//         client->tlsWrapper = nullptr;
//     }
//     clientManager->removeClient(clientId);
// }
void VPNServer::handleClient(int clientId) {
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (!client) return;

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    client->tlsWrapper = new TLSWrapper(true);
    
    if (!client->tlsWrapper->loadCertificates(certFile, keyFile)) {
        std::cerr << "[TLS] Failed to load certificates for client " << clientId << "\n";
        client->tlsWrapper->cleanup();
        delete client->tlsWrapper;
        client->tlsWrapper = nullptr;
        clientManager->removeClient(clientId);
        return;
    }
    
    std::cout << "[TLS] Starting handshake with client " << clientId 
              << " (FD: " << client->socket << ")\n";
    
    // ✅ Set blocking mode for handshake
    #ifndef _WIN32
    int flags = fcntl(client->socket, F_GETFL, 0);
    fcntl(client->socket, F_SETFL, flags & ~O_NONBLOCK);
    #endif
    
    if (!client->tlsWrapper->initTLS(client->socket)) {
        std::cerr << "[TLS] Handshake failed with client " << clientId << "\n";
        goto cleanup;
    }
    
    std::cout << "[CLIENT] " << clientId << " TLS secured from " 
              << client->realIP << ":" << client->port << "\n";

    // ✅ CRITICAL: Set socket timeout để tránh blocking vĩnh viễn
    #ifndef _WIN32
    struct timeval tv;
    tv.tv_sec = 30;  // 30 second timeout
    tv.tv_usec = 0;
    setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    #endif

    // Send welcome over TLS
    {
        std::string welcomeMsg = "WELCOME|VPN Server 2.0.0 TLS|Ready\n";
        int sent = client->tlsWrapper->send(welcomeMsg.c_str(), welcomeMsg.length());
        if (sent <= 0) {
            std::cerr << "[TLS] Failed to send welcome message (sent: " << sent << ")\n";
            goto cleanup;
        }
        std::cout << "[TLS] Welcome message sent (" << sent << " bytes)\n";
    }

    // Main loop - receive over TLS
    {
        char buffer[4096];
        std::string messageBuffer;
        
        while (!shouldStop && client->socket != INVALID_SOCKET) {
            int bytesReceived = client->tlsWrapper->recv(buffer, sizeof(buffer));
            
            if (bytesReceived <= 0) {
                int err = SSL_get_error(client->tlsWrapper->getSSL(), bytesReceived);
                
                // ✅ WANT_READ/WANT_WRITE là bình thường với non-blocking
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                
                // ✅ ZERO_RETURN = clean shutdown
                if (err == SSL_ERROR_ZERO_RETURN) {
                    std::cout << "[CLIENT] " << clientId << " closed connection cleanly\n";
                    break;
                }
                
                // ✅ SYSCALL error với errno = 0 = EOF
                if (err == SSL_ERROR_SYSCALL) {
                    if (errno == 0) {
                        std::cout << "[CLIENT] " << clientId << " disconnected (EOF)\n";
                    } else {
                        std::cout << "[CLIENT] " << clientId << " disconnected (errno: " 
                                  << errno << " - " << strerror(errno) << ")\n";
                    }
                    break;
                }
                
                std::cerr << "[CLIENT] " << clientId << " SSL error: " << err << "\n";
                ERR_print_errors_fp(stderr);
                break;
            }

            messageBuffer.append(buffer, bytesReceived);
            
            if (messageBuffer.size() > 65536) {
                std::cerr << "[SECURITY] Buffer overflow detected\n";
                break;
            }

            // Process commands
            size_t newline;
            while ((newline = messageBuffer.find('\n')) != std::string::npos) {
                std::string line = messageBuffer.substr(0, newline);
                messageBuffer.erase(0, newline + 1);
                
                std::cout << "[CMD] Client " << clientId << ": " << line.substr(0, 50) << "\n";
                
                if (line.rfind("AUTH ", 0) == 0) {
                    std::istringstream iss(line);
                    std::string cmd, username, password;
                    iss >> cmd >> username >> password;
                    
                    if (!handleAuthCommand(clientId, iss)) break;
                }
                else if (line == "UDP_KEY_REQUEST") {
                    if (!clientManager->isClientAuthenticated(clientId)) {
                        sendTLS(clientId, "ERROR|Not authenticated\n");
                        continue;
                    }
                    
                    std::vector<uint8_t> udpKey(32);
                    if (RAND_bytes(udpKey.data(), 32) != 1) {
                        sendTLS(clientId, "UDP_KEY_FAIL|Key generation failed\n");
                        continue;
                    }
                    
                    if (!clientManager->setupUDPCrypto(clientId, udpKey)) {
                        sendTLS(clientId, "UDP_KEY_FAIL|Setup failed\n");
                        continue;
                    }
                    
                    std::string response = "UDP_KEY|";
                    response.append((char*)udpKey.data(), 32);
                    response += "\n";
                    
                    if (client->tlsWrapper->send(response.c_str(), response.length()) <= 0) {
                        std::cerr << "[TLS] Failed to send UDP key\n";
                        break;
                    }
                    std::cout << "[CRYPTO] UDP key sent to client " << clientId << "\n";
                }
                else if (line == "PING") {
                    handlePingCommand(clientId);
                }
                else if (line == "GET_STATUS") {
                    handleStatusCommand(clientId);
                }
                else if (line == "DISCONNECT") {
                    sendTLS(clientId, "BYE|Goodbye\n");
                    goto cleanup;
                }
                else {
                    sendTLS(clientId, "ERROR|Unknown command\n");
                }
            }
        }
    }

cleanup:
    if (client->tlsWrapper) {
        client->tlsWrapper->cleanup();
        delete client->tlsWrapper;
        client->tlsWrapper = nullptr;
    }
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
            
            std::string response = "AUTH_OK|VPN_IP:" + vpnIP + 
                     "|SERVER_IP:10.8.0.1|SUBNET:10.8.0.0/24"
                     "|UDP_PORT:5502"
                     "|CLIENT_ID:" + std::to_string(clientId) + "\n";
                     
            sendTLS(clientId, response);
        } else {
            sendTLS(clientId, "AUTH_FAIL|No VPN IP available\n");
        }
    } else {
        sendTLS(clientId, "AUTH_FAIL|Invalid credentials\n");
    }
    
    return true;
}

bool VPNServer::handlePingCommand(int clientId) {
    std::string pongMsg = "PONG|" + std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) + "\n";
    
    std::cout << "[DEBUG] Sending PONG to client " << clientId << ": " << pongMsg;
    
    //clientManager->sendToClient(clientId, pongMsg);
    sendTLS(clientId, pongMsg);
    
    std::cout << "[DEBUG] PONG sent successfully\n";
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
        //clientManager->sendToClient(clientId, status);
        sendTLS(clientId, status);
        std::cout << "[DEBUG] STATUS sent to client " << clientId << "\n";
    } else {
        //clientManager->sendToClient(clientId, "ERROR|Not authenticated\n");
        sendTLS(clientId, "ERROR|Not authenticated\n");
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