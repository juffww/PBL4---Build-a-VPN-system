#ifndef SOCKET_MANAGER_H
#define SOCKET_MANAGER_H
#include <string>
#include <vector>
class SocketManager {
public:
    SocketManager();
    ~SocketManager();
    bool initialize();
    void cleanup();
    int createTCPSocket();
    int createUDPSocket();
    bool bindSocket(int sock, const std::string& address, int port);
    bool connectSocket(int sock, const std::string& address, int port);
    bool listenSocket(int sock, int backlog = 5);
    int acceptConnection(int sock, std::string& clientIP, int& clientPort);
    void closeSocket(int sock);
    int sendData(int sock, const char* data, int length);
    int receiveData(int sock, char* buffer, int bufferSize);
    std::string getLocalIP();
    bool isValidIP(const std::string& ip);
    std::vector<std::string> getNetworkInterfaces();
    std::string getLastError();
private:
    bool initialized;
};
#endif