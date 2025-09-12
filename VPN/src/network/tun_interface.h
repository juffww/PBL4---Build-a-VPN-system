#ifndef TUN_INTERFACE_H
#define TUN_INTERFACE_H
#include <string>
#include <atomic>
#include <cstdint>
class TUNInterface {
private:
    std::string interfaceName;
    std::atomic<bool> isOpen;
    int tunFd;
    std::string vpnIP;
    std::string subnetMask;
    std::string serverIP;
    uint64_t bytesReceived;
    uint64_t bytesSent;
    bool configureServerMode();
    bool configureClientMode();
public:
    TUNInterface(const std::string& name = "tun0");
    ~TUNInterface();
    bool create();
    bool configure(const std::string& ip, const std::string& mask, const std::string& server = "", bool isServerMode = false);
    bool setIP(const std::string& ip, const std::string& mask);
    bool setRoutes();
    std::string getDefaultGateway();
    std::string getDefaultInterface();
    bool executeCommand(const std::string& cmd);
    int readPacket(char* buffer, int maxSize);
    int writePacket(const char* buffer, int size);
    void close();
    void resetStats();
    std::string getName() const { return interfaceName; }
    std::string getIP() const { return vpnIP; }
    std::string getMask() const { return subnetMask; }
    bool isOpened() const { return isOpen.load(); }
    uint64_t getBytesReceived() const { return bytesReceived; }
    uint64_t getBytesSent() const { return bytesSent; }
};
#endif
