#include "tunnel_manager.h"
#include "tun_interface.h"
#include "packet_handler.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <thread>
#include <chrono>
#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <sys/socket.h>
    #include <errno.h>
#endif

TunnelManager::TunnelManager(const std::string& interfaceName)
    : tunInterface(nullptr), tunnelThreadRunning(false), 
      packetHandler(nullptr), interfaceName(interfaceName) {
}

TunnelManager::~TunnelManager() {
    stop();
    if (tunInterface) {
        delete tunInterface;
        tunInterface = nullptr;
    }
}

bool TunnelManager::initialize(const std::string& serverIP, const std::string& subnet, PacketHandler* handler) {
    std::cout << "[TUNNEL] Initializing...\n";
    
    packetHandler = handler;
    
    tunInterface = new TUNInterface(interfaceName);
    if (!tunInterface->create()) {
        std::cout << "[ERROR] Cannot create TUN interface\n";
        return false;
    }
    
    if (!tunInterface->configure(serverIP, "24", "", true)) {
        std::cout << "[ERROR] Cannot configure TUN interface\n";
        return false;
    }
    
    setupVPNRouting(subnet);
    
    std::cout << "[TUNNEL] Ready: " << tunInterface->getName() 
              << " (" << tunInterface->getIP() << "/" << tunInterface->getMask() << ")\n";
    
    return true;
}

void TunnelManager::setupVPNRouting(const std::string& subnet) {
    std::string routeCmd = "ip route add " + subnet + "/24 dev " + tunInterface->getName() + " 2>/dev/null || true";
    tunInterface->executeCommand(routeCmd);
    
    setupNATRules(subnet);
}

void TunnelManager::setupNATRules(const std::string& subnet) {
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) {
        defaultInterface = "eth0";
    }
    
    std::string subnetWithMask = subnet + ".0/24";
    
    tunInterface->executeCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");
    
    tunInterface->executeCommand("iptables -t nat -D POSTROUTING -s " + subnetWithMask + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -s " + subnetWithMask + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -d " + subnetWithMask + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -i " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -o " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    
    tunInterface->executeCommand("iptables -t nat -A POSTROUTING -s " + subnetWithMask + " -o " + defaultInterface + " -j MASQUERADE");
    tunInterface->executeCommand("iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -s " + subnetWithMask + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -d " + subnetWithMask + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -i " + interfaceName + " -j ACCEPT");
    tunInterface->executeCommand("iptables -A FORWARD -o " + interfaceName + " -j ACCEPT");
    
    std::cout << "[TUNNEL] NAT configured for " << defaultInterface << "\n";
}

void TunnelManager::start() {
    if (!tunInterface || !tunInterface->isOpened()) {
        std::cout << "[ERROR] TUN interface not ready\n";
        return;
    }
    
    tunnelThreadRunning = true;
    
    readThread = std::thread(&TunnelManager::readPackets, this);
    processThread = std::thread(&TunnelManager::processPacketsLoop, this);
    
    std::cout << "[TUNNEL] Multi-threaded processing started (2 threads)\n";
}

void TunnelManager::stop() {
    tunnelThreadRunning = false;
    
    if (readThread.joinable()) {
        readThread.join();
    }
    if (processThread.joinable()) {
        processThread.join();
    }
    
    if (tunInterface) {
        cleanupNATRules();
    }
    
    std::cout << "[TUNNEL] Threads stopped\n";
}

void TunnelManager::readPackets() {
    PacketBatch batch;
    int consecutiveErrors = 0;
    const int maxErrors = 10;
    
    std::cout << "[TUNNEL] Read thread started (TID: " << std::this_thread::get_id() << ")\n";
    
    while (tunnelThreadRunning && tunInterface && tunInterface->isOpened()) {
        int packetsRead = tunInterface->readPacketBatch(batch);
        
        if (packetsRead > 0) {
            consecutiveErrors = 0;
            
            // Xử lý từng packet trong batch
            for (int i = 0; i < batch.count; i++) {
                if (batch.sizes[i] >= 20) {
                    if (!enqueuePacket(batch.buffers[i], batch.sizes[i])) {
                        std::this_thread::sleep_for(std::chrono::microseconds(50));
                    }
                }
            }
        } 
        else if (packetsRead == 0 || (packetsRead < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        } 
        else {
            consecutiveErrors++;
            if (consecutiveErrors >= maxErrors) {
                std::cout << "[ERROR] Too many TUN read errors, stopping read thread\n";
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    std::cout << "[TUNNEL] Read thread exited\n";
}

// Thay thế hàm injectPacket() (dòng 237-243)
bool TunnelManager::injectPacket(const char* packet, int size) {
    if (!tunInterface || !tunInterface->isOpened()) {
        return false;
    }
    
    // Tạo batch với 1 packet
    PacketBatch batch;
    batch.count = 1;
    memcpy(batch.buffers[0], packet, size);
    batch.sizes[0] = size;
    
    int written = tunInterface->writePacketBatch(batch);
    return (written > 0);
}

void TunnelManager::processPacketsLoop() {
    PacketBuffer packet;
    
    std::cout << "[TUNNEL] Process thread started (TID: " << std::this_thread::get_id() << ")\n";
    
    while (tunnelThreadRunning) {
        if (dequeuePacket(packet)) {
            // Có packet → xử lý
            processIPPacket(packet.data, packet.size);
        } else {
            // Queue rỗng → sleep ngắn
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    
    std::cout << "[TUNNEL] Process thread exited\n";
}

bool TunnelManager::enqueuePacket(const char* data, int size) {
    int currentWrite = writeIndex.load(std::memory_order_relaxed);
    int nextWrite = (currentWrite + 1) % QUEUE_SIZE;
    
    // Kiểm tra queue full
    if (nextWrite == readIndex.load(std::memory_order_acquire)) {
        return false; // Queue full
    }
    
    // Copy data
    memcpy(packetQueue[currentWrite].data, data, size);
    packetQueue[currentWrite].size = size;
    
    // Update write index
    writeIndex.store(nextWrite, std::memory_order_release);
    return true;
}

bool TunnelManager::dequeuePacket(PacketBuffer& packet) {
    int currentRead = readIndex.load(std::memory_order_relaxed);
    
    // Kiểm tra queue empty
    if (currentRead == writeIndex.load(std::memory_order_acquire)) {
        return false; // Queue empty
    }
    
    // Copy packet
    packet = packetQueue[currentRead];
    
    // Update read index
    int nextRead = (currentRead + 1) % QUEUE_SIZE;
    readIndex.store(nextRead, std::memory_order_release);
    return true;
}

void TunnelManager::processIPPacket(const char* packet, int size) {
    if (!packetHandler) return;
    
    struct iphdr {
        uint8_t version_ihl;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };
    
    iphdr* ip_header = (iphdr*)packet;
    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, 16);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, 16);
    
    packetHandler->handleTUNPacket(packet, size, std::string(src_ip), std::string(dst_ip));
}

void TunnelManager::cleanupNATRules() {
    if (!tunInterface) return;
    
    std::string defaultInterface = tunInterface->getDefaultInterface();
    if (defaultInterface.empty()) defaultInterface = "eth0";
    
    std::string subnet = "10.8.0.0/24";
    tunInterface->executeCommand("iptables -t nat -D POSTROUTING -s " + subnet + " -o " + defaultInterface + " -j MASQUERADE 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -s " + subnet + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -d " + subnet + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -i " + interfaceName + " -j ACCEPT 2>/dev/null || true");
    tunInterface->executeCommand("iptables -D FORWARD -o " + interfaceName + " -j ACCEPT 2>/dev/null || true");
}

TUNInterface* TunnelManager::getTUNInterface() const {
    return tunInterface;
}

bool TunnelManager::isRunning() const {
    return tunnelThreadRunning;
}

std::string TunnelManager::getInterfaceName() const {
    return interfaceName;
}

long long TunnelManager::getBytesReceived() const {
    return tunInterface ? tunInterface->getBytesReceived() : 0;
}

long long TunnelManager::getBytesSent() const {
    return tunInterface ? tunInterface->getBytesSent() : 0;
}