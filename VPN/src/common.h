#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <chrono>

// Platform-specific socket definitions
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET SOCKET_TYPE;
    #define INVALID_SOCKET INVALID_SOCKET
    #define SOCKET_ERROR SOCKET_ERROR
    #define MSG_NOSIGNAL 0
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    typedef int SOCKET_TYPE;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define MSG_NOSIGNAL MSG_NOSIGNAL
    #define closesocket close
#endif

// Common structures
struct ClientInfo {
    int id;
    SOCKET_TYPE socket;
    std::string username;
    std::string realIP;
    int port;
    std::string assignedVpnIP;
    std::string connectTime;
    std::chrono::steady_clock::time_point connectedAt;
    bool authenticated;
    bool ipAssigned;
    long long bytesSent;
    long long bytesReceived;
    
    ClientInfo() : id(0), socket(INVALID_SOCKET), port(0), authenticated(false), 
                   ipAssigned(false), bytesSent(0), bytesReceived(0) {}
};

struct PacketStats {
    long long totalPackets;
    long long totalBytes;
    long long packetsToClients;
    long long bytesToClients;
    long long packetsFromClients;
    long long bytesFromClients;
    long long packetsToInternet;
    long long bytesToInternet;
    
    PacketStats() : totalPackets(0), totalBytes(0), packetsToClients(0), 
                    bytesToClients(0), packetsFromClients(0), bytesFromClients(0),
                    packetsToInternet(0), bytesToInternet(0) {}
};

#endif // COMMON_H