#ifndef TUNNEL_MANAGER_H
#define TUNNEL_MANAGER_H

#include "network/tun_interface.h"
#include "packet_handler.h"
#include <string>
#include <memory>
#include <thread>
#include <atomic>

class ClientManager;

class TunnelManager {
public:
    TunnelManager(const std::string& interface, const std::string& ip, const std::string& mask);
    ~TunnelManager();

    bool initialize();
    void start();
    void stop();
    bool setupNATRules();
    bool clearNATRules();
    bool executeCommand(const std::string& cmd);
    void processTUN();
    bool injectPacket(const char* packet, int size);
    void setClientManager(ClientManager* clientManager);
    TUNInterface* getTUNInterface() const;

private:
    TUNInterface* tunInterface;
    PacketHandler* packetHandler;
    std::atomic<bool> running;
    std::thread workerThread;

    void processIPPacket(const char* packet, int size);
};

#endif // TUNNEL_MANAGER_H