// tun_interface.h - Linux only implementation
#ifndef TUN_INTERFACE_H
#define TUN_INTERFACE_H

#include <string>
#include <functional>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

class TUNInterface {
private:
    std::string interfaceName;
    std::string vpnIP;
    std::string subnetMask;
    std::string serverIP;
    bool isOpen;
    int tunFd;
    uint64_t bytesReceived;
    uint64_t bytesSent;
    
public:
    TUNInterface(const std::string& name = "vpn0");
    ~TUNInterface();
    
    bool create();
    bool configure(const std::string& ip, const std::string& mask = "255.255.255.0", 
                   const std::string& server = "");
    bool setRoutes();
    void close();
    
    // Đọc/ghi packets
    int readPacket(char* buffer, int maxSize);
    int writePacket(const char* buffer, int size);
    
    // Traffic monitoring
    uint64_t getBytesReceived() const { return bytesReceived; }
    uint64_t getBytesSent() const { return bytesSent; }
    void resetStats();
    
    // Interface info
    std::string getInterfaceName() const { return interfaceName; }
    std::string getVPNIP() const { return vpnIP; }
    
private:
    bool setIP(const std::string& ip, const std::string& mask);
    bool addRoute(const std::string& network, const std::string& gateway);
    bool executeCommand(const std::string& cmd);
};