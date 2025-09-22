#include "socket_manager.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <vector>
SocketManager::SocketManager() : initialized(false) {}
SocketManager::~SocketManager() { cleanup(); }
bool SocketManager::initialize() { initialized = true; return true; }
void SocketManager::cleanup() { initialized = false; }
int SocketManager::createTCPSocket() {
    if (!initialize()) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) std::cerr << "[ERROR] Failed to create TCP socket: " << getLastError() << std::endl;
    return sock;
}
int SocketManager::createUDPSocket() {
    if (!initialize()) return -1;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) std::cerr << "[ERROR] Failed to create UDP socket: " << getLastError() << std::endl;
    return sock;
}
bool SocketManager::bindSocket(int sock, const std::string& address, int port) {
    if (sock == -1) return false;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (address.empty() || address == "0.0.0.0") addr.sin_addr.s_addr = INADDR_ANY;
    else {
        addr.sin_addr.s_addr = inet_addr(address.c_str());
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            std::cerr << "[ERROR] Invalid IP address: " << address << std::endl;
            return false;
        }
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "[ERROR] Bind failed: " << getLastError() << std::endl;
        return false;
    }
    return true;
}
bool SocketManager::connectSocket(int sock, const std::string& address, int port) {
    if (sock == -1) return false;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address.c_str());
    if (addr.sin_addr.s_addr == INADDR_NONE) {
        std::cerr << "[ERROR] Invalid IP address: " << address << std::endl;
        return false;
    }
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "[ERROR] Connect failed: " << getLastError() << std::endl;
        return false;
    }
    return true;
}
bool SocketManager::listenSocket(int sock, int backlog) {
    if (sock == -1) return false;
    if (listen(sock, backlog) == -1) {
        std::cerr << "[ERROR] Listen failed: " << getLastError() << std::endl;
        return false;
    }
    return true;
}
int SocketManager::acceptConnection(int sock, std::string& clientIP, int& clientPort) {
    if (sock == -1) return -1;
    struct sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    int clientSock = accept(sock, (struct sockaddr*)&clientAddr, &clientLen);
    if (clientSock == -1) {
        std::cerr << "[ERROR] Accept failed: " << getLastError() << std::endl;
        return -1;
    }
    clientIP = inet_ntoa(clientAddr.sin_addr);
    clientPort = ntohs(clientAddr.sin_port);
    return clientSock;
}
void SocketManager::closeSocket(int sock) {
    if (sock != -1) close(sock);
}
int SocketManager::sendData(int sock, const char* data, int length) {
    if (sock == -1 || !data) return -1;
    int sent = send(sock, data, length, 0);
    if (sent == -1) std::cerr << "[ERROR] Send failed: " << getLastError() << std::endl;
    return sent;
}
int SocketManager::receiveData(int sock, char* buffer, int bufferSize) {
    if (sock == -1 || !buffer) return -1;
    int received = recv(sock, buffer, bufferSize, 0);
    if (received == -1) std::cerr << "[ERROR] Receive failed: " << getLastError() << std::endl;
    return received;
}
std::string SocketManager::getLocalIP() {
    struct ifaddrs* ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs* ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                std::string addr = inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr);
                if (addr != "127.0.0.1" && (ifa->ifa_flags & IFF_RUNNING)) {
                    freeifaddrs(ifaddrs_ptr);
                    return addr;
                }
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }
    return "127.0.0.1";
}
bool SocketManager::isValidIP(const std::string& ip) {
    struct sockaddr_in sa{};
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}
std::vector<std::string> SocketManager::getNetworkInterfaces() {
    std::vector<std::string> interfaces;
    struct ifaddrs* ifaddrs_ptr;
    if (getifaddrs(&ifaddrs_ptr) == 0) {
        for (struct ifaddrs* ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                if ((ifa->ifa_flags & IFF_RUNNING) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
                    interfaces.push_back(inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr));
                }
            }
        }
        freeifaddrs(ifaddrs_ptr);
    }
    if (interfaces.empty()) interfaces.push_back("127.0.0.1");
    return interfaces;
}
std::string SocketManager::getLastError() {
    return strerror(errno);
}