#ifndef TUN_INTERFACE_H
#define TUN_INTERFACE_H

#include <string>
#include <atomic>
#include <cstdint>

class TUNInterface {
private:
    std::string interfaceName;
    std::atomic<bool> isOpen;
    int tunFd;                 // file descriptor / handle OS-specific
    std::string vpnIP;
    std::string subnetMask;
    std::string serverIP;      // IP của VPN server để set route
    uint64_t bytesReceived;
    uint64_t bytesSent;

    // OS-specific internal functions, sẽ implement trong cpp theo OS
    bool configureClientMode();

    std::string findTAPAdapter();
    std::string getAdapterFriendlyName();

public:
    TUNInterface(const std::string& name = "tun0");
    ~TUNInterface();

    // Tạo TUN interface, OS-specific
    bool create();

    // Configure IP và routes client, serverIP dùng để giữ route đến server
    bool configure(const std::string& ip, const std::string& mask,
                   const std::string& server = "");

    bool setIP(const std::string& ip, const std::string& mask);
    bool setRoutes();
    std::string getDefaultGateway();
    std::string getDefaultInterface();

    // Hỗ trợ chạy lệnh OS-specific (Linux/macOS/Windows)
    bool executeCommand(const std::string& cmd);

    // Đọc/ghi packet từ TUN
    int readPacket(char* buffer, int maxSize);
    int writePacket(const char* buffer, int size);

    void close();
    void resetStats();

    // Getter
    std::string getName() const { return interfaceName; }
    std::string getIP() const { return vpnIP; }
    std::string getMask() const { return subnetMask; }
    bool isOpened() const { return isOpen.load(); }
    uint64_t getBytesReceived() const { return bytesReceived; }
    uint64_t getBytesSent() const { return bytesSent; }

    std::string getInterfaceIndex();
};

#endif
