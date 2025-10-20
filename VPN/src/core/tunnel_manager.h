#ifndef TUNNEL_MANAGER_H
#define TUNNEL_MANAGER_H

#include <string>
#include <thread>
#include <atomic>
#include "../network/tun_interface.h"

// Forward declaration
class PacketHandler;

class TunnelManager {
private:
    TUNInterface* tunInterface;
    std::thread tunnelThread;
    std::atomic<bool> tunnelThreadRunning;
    PacketHandler* packetHandler;
    std::string interfaceName;
    
    void processPackets();
    void processIPPacket(const char* packet, int size);
    void setupVPNRouting(const std::string& subnet);
    void setupNATRules(const std::string& subnet);
    void cleanupNATRules();

public:
    explicit TunnelManager(const std::string& interfaceName = "tun0");
    ~TunnelManager();
    
    bool initialize(const std::string& serverIP, const std::string& subnet, PacketHandler* handler);
    void start();
    void stop();
    
    bool injectPacket(const char* packet, int size);
    
    TUNInterface* getTUNInterface() const;
    bool isRunning() const;
    std::string getInterfaceName() const;
    long long getBytesReceived() const;
    long long getBytesSent() const;
};

#endif 