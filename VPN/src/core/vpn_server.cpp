#include "vpn_server.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <csignal>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
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
    
    signal(SIGPIPE, SIG_IGN);

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
        std::cout << "[ERROR] Cannot create UDP socket: " << strerror(errno) << "\n";
        return false;
    }

    int opt = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR,
                   (char*)&opt, sizeof(opt)) < 0) {
        std::cout << "[WARN] Cannot set SO_REUSEADDR on UDP socket\n";
    }

    struct sockaddr_in udpAddr;
    memset(&udpAddr, 0, sizeof(udpAddr));
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_addr.s_addr = INADDR_ANY;
    udpAddr.sin_port = htons(5502);

    if (bind(udpSocket, (struct sockaddr*)&udpAddr, sizeof(udpAddr)) < 0) {
        std::cout << "[ERROR] Cannot bind UDP socket on port 5502: "
                  << strerror(errno) << "\n";
        close(udpSocket);
        udpSocket = INVALID_SOCKET;
        return false;
    }

    std::cout << "[SERVER] UDP socket bound successfully on port 5502\n";
    std::cout << "[SERVER] Ready on TCP:" << serverPort << " UDP:5502\n";
    
    return true;
}

std::string base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string res(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return res;
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

// void VPNServer::handleClient(int clientId) {
//     ClientInfo* client = clientManager->getClientInfo(clientId);
//     if (!client) return;

//     #ifndef _WIN32
//     int flags = 0;
//     int flag = 1;
//     int keepalive = 1;
//     int keepidle = 60;
//     int keepintvl = 10;
//     int keepcnt = 3;
//     struct timeval tv;
//     #endif
//     char buffer[8192];
//     std::string messageBuffer;
//     int consecutiveErrors = 0;
//     const int maxConsecutiveErrors = 5;

//     client->tlsWrapper = new TLSWrapper(true);

//     if (!client->tlsWrapper->loadCertificates(certFile, keyFile)) {
//         std::cerr << "[TLS] Failed to load certificates for client " << clientId << "\n";
//         goto cleanup;
//     }

//     std::cout << "[TLS] Starting handshake with client " << clientId
//               << " (FD: " << client->socket << ")\n";

//     #ifndef _WIN32
//     flags = fcntl(client->socket, F_GETFL, 0);
//     if (flags == -1) {
//         std::cerr << "[TLS] Failed to get socket flags\n";
//         goto cleanup;
//     }
//     fcntl(client->socket, F_SETFL, flags & ~O_NONBLOCK);
//     #endif

//     if (!client->tlsWrapper->initTLS(client->socket)) {
//         std::cerr << "[TLS] Handshake failed with client " << clientId << "\n";
//         goto cleanup;
//     }

//     std::cout << "[CLIENT] " << clientId << " TLS secured from "
//               << client->realIP << ":" << client->port << "\n";

//     #ifndef _WIN32
//     fcntl(client->socket, F_SETFL, flags | O_NONBLOCK);
//     std::cout << "[TLS] Socket set to non-blocking mode after handshake\n";
//     #endif

//     #ifndef _WIN32
//     tv.tv_sec = 5;
//     tv.tv_usec = 0;
//     setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
//     setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
//     setsockopt(client->socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    
//     setsockopt(client->socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
//     setsockopt(client->socket, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
//     setsockopt(client->socket, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
//     setsockopt(client->socket, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
//     #endif

//     {
//         std::string welcomeMsg = "WELCOME|VPN Server 2.0.0 TLS|Ready\n";
//         int sent = client->tlsWrapper->send(welcomeMsg.c_str(), welcomeMsg.length());
//         if (sent <= 0) {
//             int err = SSL_get_error(client->tlsWrapper->getSSL(), sent);
//             if (err != SSL_ERROR_WANT_WRITE) {
//                 std::cerr << "[TLS] Failed to send welcome message (error: " << err << ")\n";
//                 ERR_print_errors_fp(stderr);
//                 goto cleanup;
//             }
//             std::this_thread::sleep_for(std::chrono::milliseconds(10));
//             sent = client->tlsWrapper->send(welcomeMsg.c_str(), welcomeMsg.length());
//             if (sent <= 0) {
//                 std::cerr << "[TLS] Failed to send welcome message after retry\n";
//                 goto cleanup;
//             }
//         }
//         std::cout << "[TLS] Welcome message sent (" << sent << " bytes)\n";
//     }

//     {
//         while (!shouldStop && client->socket != INVALID_SOCKET) {
//             int bytesReceived = client->tlsWrapper->recv(buffer, sizeof(buffer));
            
//             if (bytesReceived <= 0) {
//                 int err = SSL_get_error(client->tlsWrapper->getSSL(), bytesReceived);

//                 if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
//                     std::this_thread::sleep_for(std::chrono::milliseconds(50));
//                     consecutiveErrors = 0; 
//                     continue;
//                 }
                
//                 if (err == SSL_ERROR_ZERO_RETURN) {
//                     std::cout << "[CLIENT] " << clientId << " closed connection cleanly\n";
//                     break;
//                 }
                
//                 if (err == SSL_ERROR_SYSCALL) {
//                     if (errno == 0) {
//                         std::cout << "[CLIENT] " << clientId << " disconnected (EOF)\n";
//                     } else {
//                         std::cout << "[CLIENT] " << clientId << " disconnected (errno: " 
//                                   << errno << " - " << strerror(errno) << ")\n";
//                     }
//                     break;
//                 }
                
//                 consecutiveErrors++;
//                 if (consecutiveErrors >= maxConsecutiveErrors) {
//                     std::cerr << "[CLIENT] " << clientId << " too many errors, disconnecting\n";
//                     break;
//                 }
                
//                 std::cerr << "[CLIENT] " << clientId << " SSL error: " << err << "\n";
//                 ERR_print_errors_fp(stderr);
//                 std::this_thread::sleep_for(std::chrono::milliseconds(100));
//                 continue;
//             }

//             consecutiveErrors = 0;

//             messageBuffer.append(buffer, bytesReceived);
            
//             if (messageBuffer.size() > 65536) {
//                 std::cerr << "[SECURITY] Buffer overflow detected from client " << clientId << "\n";
//                 break;
//             }

//             size_t newline;
//             while ((newline = messageBuffer.find('\n')) != std::string::npos) {
//                 std::string line = messageBuffer.substr(0, newline);
//                 messageBuffer.erase(0, newline + 1);
                
//                 line.erase(line.find_last_not_of(" \n\r\t") + 1);
//                 if (line.empty()) continue;
                
//                 std::cout << "[CMD] Client " << clientId << ": " 
//                           << line.substr(0, std::min(size_t(50), line.size())) << "\n";
                
//                 if (line == "AUTH") {
//                     if (!handleAuthCommand(clientId)) 
//                     {
//                         std::cout << "Error: Authentication failed\n";
//                         break;
//                     }
//                 }
//                 else if (line == "UDP_KEY_REQUEST") {
//                     if (!clientManager->isClientAuthenticated(clientId)) {
//                         sendTLS(clientId, "ERROR|Not authenticated\n");
//                         std::cout << "Error: Not authenticated\n";
//                         continue;
//                     }
                    
//                     std::vector<uint8_t> udpKey(32);
//                     if (RAND_bytes(udpKey.data(), 32) != 1) {
//                         sendTLS(clientId, "UDP_KEY_FAIL|Key generation failed\n");
//                         std::cout << "Error: Not authenticated\n";
//                         continue;
//                     }
                    
//                     if (!clientManager->setupUDPCrypto(clientId, udpKey)) {
//                         sendTLS(clientId, "UDP_KEY_FAIL|Setup failed\n");
//                         std::cout << "Error: Not authenticated\n";
//                         continue;
//                     }
                    
//                     std::string response = "UDP_KEY|";
//                     response.append((char*)udpKey.data(), 32);
//                     response += "\n";
//                     // std::string b64Key = base64_encode(udpKey.data(), udpKey.size());
    
//                     // std::string response = "UDP_KEY|" + b64Key + "\n";
                    
//                     int sent = client->tlsWrapper->send(response.c_str(), response.length());
//                     if (sent <= 0) {
//                         int err = SSL_get_error(client->tlsWrapper->getSSL(), sent);
//                         if (err == SSL_ERROR_WANT_WRITE) {
//                             std::this_thread::sleep_for(std::chrono::milliseconds(10));
//                             sent = client->tlsWrapper->send(response.c_str(), response.length());
//                         }
//                         if (sent <= 0) {
//                             std::cerr << "[TLS] Failed to send UDP key\n";
//                             break;
//                         }
//                     }
//                     std::cout << "[CRYPTO] UDP key sent to client " << clientId
//                               << " (" << sent << " bytes)\n";
//                 }
//                 else if (line == "PING") {
//                     handlePingCommand(clientId);
//                 }
//                 else if (line == "GET_STATUS") {
//                     handleStatusCommand(clientId);
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
//     std::cout << "[CLIENT] " << clientId << " cleaning up\n";
//     // if (client->tlsWrapper) {
//     //     client->tlsWrapper->cleanup();
//     //     delete client->tlsWrapper;
//     //     client->tlsWrapper = nullptr;
//     // }
//     // clientManager->removeClient(clientId);
//     // Lấy lại pointer để cleanup TLS
//     ClientInfo* clientToClean = clientManager->getClientInfo(clientId);
//     if (clientToClean && clientToClean->tlsWrapper) {
//         clientToClean->tlsWrapper->cleanup();
//         delete clientToClean->tlsWrapper;
//         clientToClean->tlsWrapper = nullptr;
//     }

//     // Cuối cùng mới xóa khỏi map
//     clientManager->removeClient(clientId);
// }

void VPNServer::handleClient(int clientId) {
    // Lấy thông tin client ban đầu
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (!client) return;

    // Các biến cấu hình Socket
    #ifndef _WIN32
    int flags = 0;
    int flag = 1;
    int keepalive = 1;
    int keepidle = 60;
    int keepintvl = 10;
    int keepcnt = 3;
    struct timeval tv;
    #endif

    char buffer[8192];
    std::string messageBuffer;
    int consecutiveErrors = 0;
    const int maxConsecutiveErrors = 5;

    // --- 1. KHỞI TẠO TLS ---
    client->tlsWrapper = new TLSWrapper(true);

    if (!client->tlsWrapper->loadCertificates(certFile, keyFile)) {
        std::cerr << "[TLS] Failed to load certificates for client " << clientId << "\n";
        goto cleanup;
    }

    std::cout << "[TLS] Starting handshake with client " << clientId
              << " (FD: " << client->socket << ")\n";

    #ifndef _WIN32
    // Đặt về Blocking mode tạm thời cho quá trình Handshake
    flags = fcntl(client->socket, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "[TLS] Failed to get socket flags\n";
        goto cleanup;
    }
    fcntl(client->socket, F_SETFL, flags & ~O_NONBLOCK);
    #endif

    // Thực hiện Handshake
    if (!client->tlsWrapper->initTLS(client->socket)) {
        std::cerr << "[TLS] Handshake failed with client " << clientId << "\n";
        goto cleanup;
    }

    std::cout << "[CLIENT] " << clientId << " TLS secured from "
              << client->realIP << ":" << client->port << "\n";

    #ifndef _WIN32
    // Đặt lại Non-blocking mode cho quá trình truyền nhận dữ liệu
    fcntl(client->socket, F_SETFL, flags | O_NONBLOCK);
    
    // Cấu hình Timeout và Keepalive
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(client->socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    setsockopt(client->socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    setsockopt(client->socket, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(client->socket, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(client->socket, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    #endif

    // --- 2. GỬI WELCOME MESSAGE ---
    {
        std::string welcomeMsg = "WELCOME|VPN Server 2.0.0 TLS|Ready\n";
        int sent = client->tlsWrapper->send(welcomeMsg.c_str(), welcomeMsg.length());
        
        // Retry logic cho Welcome message
        if (sent <= 0) {
            int err = SSL_get_error(client->tlsWrapper->getSSL(), sent);
            if (err != SSL_ERROR_WANT_WRITE) {
                std::cerr << "[TLS] Failed to send welcome message (error: " << err << ")\n";
                ERR_print_errors_fp(stderr);
                goto cleanup;
            }
            // Thử lại một lần nữa nếu socket bận
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            sent = client->tlsWrapper->send(welcomeMsg.c_str(), welcomeMsg.length());
            if (sent <= 0) {
                std::cerr << "[TLS] Failed to send welcome message after retry\n";
                goto cleanup;
            }
        }
    }

    // --- 3. VÒNG LẶP CHÍNH (MAIN LOOP) ---
    while (!shouldStop) {
        // [QUAN TRỌNG] Kiểm tra pointer an toàn mỗi vòng lặp
        // Để đảm bảo client chưa bị xóa bởi luồng khác
        ClientInfo* c = clientManager->getClientInfo(clientId);
        if (!c || c->socket == INVALID_SOCKET) break;

        // Đọc dữ liệu
        // int bytesReceived = c->tlsWrapper->recv(buffer, sizeof(buffer));
        
        // // Xử lý kết quả đọc
        // if (bytesReceived <= 0) {
        //     int err = SSL_get_error(c->tlsWrapper->getSSL(), bytesReceived);

        //     // Nếu Socket chưa có dữ liệu hoặc đang bận ghi -> Chờ và thử lại
        //     if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        //         std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Giảm CPU load
        //         consecutiveErrors = 0; 
        //         continue;
        //     }
            
        //     // Client đóng kết nối
        //     if (err == SSL_ERROR_ZERO_RETURN) {
        //         std::cout << "[CLIENT] " << clientId << " closed connection cleanly\n";
        //         break;
        //     }
            
        //     // Lỗi kết nối
        //     if (err == SSL_ERROR_SYSCALL) {
        //         if (errno == 0) {
        //             std::cout << "[CLIENT] " << clientId << " disconnected (EOF)\n";
        //         } else {
        //             std::cout << "[CLIENT] " << clientId << " disconnected (errno: " 
        //                       << errno << " - " << strerror(errno) << ")\n";
        //         }
        //         break;
        //     }
            
        //     // Đếm lỗi liên tiếp để tránh vòng lặp vô tận
        //     consecutiveErrors++;
        //     if (consecutiveErrors >= maxConsecutiveErrors) {
        //         std::cerr << "[CLIENT] " << clientId << " too many errors, disconnecting\n";
        //         break;
        //     }
            
        //     std::this_thread::sleep_for(std::chrono::milliseconds(100));
        //     continue;
        // }
        int bytesReceived = c->tlsWrapper->recv(buffer, sizeof(buffer));

        if (bytesReceived <= 0) {
            int err = SSL_get_error(c->tlsWrapper->getSSL(), bytesReceived);

            // [FIX] Xử lý lỗi gọn gàng hơn
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                consecutiveErrors = 0; 
                continue;
            }
            
            // [FIX] Chỉ in log lỗi nếu thực sự là lỗi, không in quá nhiều
            if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                std::cerr << "[CLIENT] " << clientId << " Socket error: " << err << " (" << strerror(errno) << ")\n";
            } else if (err == SSL_ERROR_ZERO_RETURN) {
                std::cout << "[CLIENT] " << clientId << " Disconnected cleanly.\n";
            }

            break; // Thoát vòng lặp ngay lập tức, không lặp lại 5 lần
        }

        consecutiveErrors = 0;

        // Xử lý Buffer (Nối dữ liệu và tách dòng lệnh)
        messageBuffer.append(buffer, bytesReceived);
        
        if (messageBuffer.size() > 65536) {
            std::cerr << "[SECURITY] Buffer overflow detected from client " << clientId << "\n";
            break;
        }

        size_t newline;
        while ((newline = messageBuffer.find('\n')) != std::string::npos) {
            std::string line = messageBuffer.substr(0, newline);
            messageBuffer.erase(0, newline + 1);
            
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            if (line.empty()) continue;
            
            std::cout << "[CMD] Client " << clientId << ": " 
                      << line.substr(0, std::min(size_t(50), line.size())) << "\n";
            
            // --- XỬ LÝ LỆNH ---
            
            // 1. Lệnh AUTH (Không mật khẩu)
            if (line == "AUTH") {
                if (!handleAuthCommand(clientId)) {
                    std::cout << "Error: Authentication failed\n";
                    goto cleanup;
                }
            }
            // 2. Lệnh UDP_KEY_REQUEST
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
                
                sendTLS(clientId, response);
                std::cout << "[CRYPTO] UDP key sent to client " << clientId << "\n";
            }
            // 3. Các lệnh khác
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

// --- 4. CLEANUP SECTION (AN TOÀN) ---
cleanup:
    std::cout << "[CLIENT] " << clientId << " cleaning up thread\n";
    
    // [QUAN TRỌNG] Lấy lại pointer để kiểm tra tính hợp lệ trước khi truy cập
    // Tránh trường hợp ClientManager đã xóa nó rồi.
    ClientInfo* clientToClean = clientManager->getClientInfo(clientId);
    
    if (clientToClean && clientToClean->tlsWrapper) {
        clientToClean->tlsWrapper->cleanup();
        delete clientToClean->tlsWrapper;
        clientToClean->tlsWrapper = nullptr;
    }

    // Cuối cùng mới xóa khỏi map quản lý
    clientManager->removeClient(clientId);
}

void VPNServer::sendTLS(int clientId, const std::string& message) {
    ClientInfo* client = clientManager->getClientInfo(clientId);
    if (!client || !client->tlsWrapper) {
        std::cerr << "[ERROR] sendTLS: Invalid client or TLS wrapper\n";
        return;
    }
    
    int totalSent = 0;
    int retries = 5;  
    
    while (totalSent < message.length() && retries > 0) {
        int sent = client->tlsWrapper->send(message.c_str() + totalSent, 
                                            message.length() - totalSent);
        
        if (sent > 0) {
            totalSent += sent;
            std::cout << "[DEBUG] sendTLS: " << sent << " bytes sent (total: " 
                      << totalSent << "/" << message.length() << ") to client " 
                      << clientId << "\n";
            
            if (totalSent >= message.length()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                return;
            }
            continue;
        }
        
        int err = SSL_get_error(client->tlsWrapper->getSSL(), sent);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            retries--;
            continue;
        }
        
        std::cerr << "[ERROR] sendTLS failed: SSL error " << err << "\n";
        ERR_print_errors_fp(stderr);
        break;
    }
    
    if (totalSent < message.length()) {
        std::cerr << "[ERROR] sendTLS incomplete: " << totalSent << "/" 
                  << message.length() << " bytes sent\n";
    }
}

void VPNServer::handleUDPPackets() {
    char buffer[65536];
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    int rcvbuf = 4194304;  
    int sndbuf = 4194304; 
    setsockopt(udpSocket, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
    setsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
    
    std::cout << "[UDP] Handler started with 4MB buffers\n";
    
    int packetsProcessed = 0;
    auto lastStatsTime = std::chrono::steady_clock::now();
    
    std::cout << "[UDP] Listening on port 5502, waiting for packets...\n";

    while (!shouldStop) {
        int n = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&clientAddr, &addrLen);

        if (n > 0) {
            packetsProcessed++;

            static int debugPacketCount = 0;
            if (debugPacketCount < 10) {
                std::cout << "[UDP] Received " << n << " bytes from "
                          << inet_ntoa(clientAddr.sin_addr) << ":"
                          << ntohs(clientAddr.sin_port) << "\n";
                debugPacketCount++;
            }
            
            if (packetsProcessed % 1000 == 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastStatsTime);
                if (elapsed.count() > 0) {
                    std::cout << "[UDP] Processed " << packetsProcessed << " packets ("
                              << (packetsProcessed / elapsed.count()) << " pps)\n";
                    packetsProcessed = 0;
                    lastStatsTime = now;
                }
            }
            
            if (n >= 8) {
                int clientId = *(int*)buffer;
                int dataSize = *(int*)(buffer + 4);

                if (clientId <= 0 || clientId > 10000) {
                    std::cerr << "[UDP] Invalid client ID: " << clientId << "\n";
                    continue;
                }

                if (dataSize == 0) {
                    std::cout << "[UDP] Handshake request from client " << clientId
                              << " (" << inet_ntoa(clientAddr.sin_addr) << ":"
                              << ntohs(clientAddr.sin_port) << ")\n";

                    {
                        std::lock_guard<std::mutex> lock(udpAddrMutex);
                        clientUDPAddrs[clientId] = clientAddr;
                    }

                    char ack[8];
                    *(int*)ack = clientId;
                    *(int*)(ack + 4) = 0;

                    int sent = sendto(udpSocket, ack, 8, 0,
                          (struct sockaddr*)&clientAddr, sizeof(clientAddr));

                    if (sent > 0) {
                        std::cout << "[UDP] Handshake ACK sent to client " << clientId
                                  << " (" << sent << " bytes)\n";
                    } else {
                        std::cerr << "[UDP] Failed to send ACK to client " << clientId
                                  << ": " << strerror(errno) << "\n";
                    }
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
        else if (n < 0) {
            if (shouldStop) {
                std::cout << "[UDP] Handler stopping...\n";
                break;
            }
            std::cerr << "[UDP] recvfrom error: " << strerror(errno) << "\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    std::cout << "[UDP] Handler stopped\n";
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
        
        // clientThreads.emplace_back([this, clientId]() {
        //     handleClient(clientId);
        // });
        // TẠO THREAD VÀ DETACH LUÔN
        std::thread([this, clientId]() {
            handleClient(clientId);
        }).detach(); // <--- SỬA THÀNH DETACH
        
        // Không cần push vào clientThreads vector nữa nếu dùng detach
        // Nếu muốn quản lý số lượng thì dùng biến đếm atomic
    }
}

bool VPNServer::processClientMessage(int clientId, const std::string& message) {
    std::istringstream iss(message);
    std::string command;
    iss >> command;
    
    if (command == "AUTH") {
        return handleAuthCommand(clientId);
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

void VPNServer::cleanupFinishedThreads() {
    auto it = clientThreads.begin();
    while (it != clientThreads.end()) {
        if (it->joinable()) {
            // Kiểm tra xem thread đã xong chưa là rất khó với std::thread cơ bản
            // Cách đơn giản nhất: detach thread ngay từ đầu nếu không cần quản lý chặt
            // HOẶC chỉ join tất cả khi stop().
            
            // Giải pháp NHANH NHẤT cho bạn: Detach thread
        }
        ++it;
    }
}

bool VPNServer::handleAuthCommand(int clientId) {
    if (clientManager->authenticateClient(clientId)) {
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
    } 
     else {
         sendTLS(clientId, "AUTH_FAIL|System error\n");
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