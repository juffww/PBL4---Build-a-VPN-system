#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <signal.h>
#include <sstream>
#include <memory>
#include <exception>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include "core/vpn_server.h"
#include "core/client_manager.h"
#include "core/tunnel_manager.h"
#include "core/packet_handler.h"
#include "network/socket_manager.h"

class VPNServerManager {
private:
    std::unique_ptr<VPNServer> server;
    bool running;
    std::thread serverThread;
    
    bool checkSystemRequirements() {
        #ifndef _WIN32
        if (getuid() != 0) {
            std::cout << "[ERROR] VPN Server requires root privileges for TUN interface\n";
            std::cout << "[INFO] Please run with: sudo ./vpn_server\n";
            return false;
        }
        
        if (system("lsmod | grep -q '^tun '") != 0) {
            std::cout << "[WARN] TUN module not loaded. Attempting to load...\n";
            if (system("modprobe tun") != 0) {
                std::cout << "[ERROR] Failed to load TUN module\n";
                return false;
            }
            std::cout << "[INFO] TUN module loaded successfully\n";
        }
        
        if (access("/dev/net/tun", F_OK) != 0) {
            std::cout << "[ERROR] /dev/net/tun not available\n";
            return false;
        }
        #endif
        return true;
    }

public:
    VPNServerManager() : server(nullptr), running(false) {}
    
    ~VPNServerManager() { 
        stop(); 
    }
    
    void start(int port = 1194) {
        if (running) {
            std::cout << "[WARN] Server đã đang chạy!\n";
            return;
        }
        
        if (!checkSystemRequirements()) {
            return;
        }
        
        try {
            server = std::unique_ptr<VPNServer>(new VPNServer(port));
            
            std::cout << "[INFO] Đang khởi tạo VPN Server...\n";
            if (server->initialize()) {
                running = true;
                
                serverThread = std::thread([this]() { 
                    try {
                        server->start(); 
                    } catch (const std::exception& e) {
                        std::cout << "[ERROR] Server exception: " << e.what() << "\n";
                        running = false;
                    }
                });
                
                std::cout << "[INFO] VPN Server đã khởi động trên cổng " << port << "\n";
                std::cout << "[INFO] Server IP: " << server->getServerIP() << "\n";
                printStatus();
            } else {
                std::cout << "[ERROR] Không thể khởi động server!\n";
                server.reset();
            }
        } catch (const std::exception& e) {
            std::cout << "[ERROR] Exception during server creation: " << e.what() << "\n";
            server.reset();
        }
    }
    
    void stop() {
        if (running && server) {
            std::cout << "[INFO] Đang dừng server...\n";
            running = false;
            
            server->stop();
            
            if (serverThread.joinable()) {
                serverThread.join();
            }
            
            server.reset();
            std::cout << "[INFO] Server đã dừng\n";
        }
    }
    
    void printStatus() {
        if (!server) {
            std::cout << "[WARN] Server chưa khởi động\n";
            return;
        }
        
        std::cout << "\n=== VPN SERVER STATUS ===\n";
        std::cout << "Trạng thái: " << (running ? "RUNNING" : "STOPPED") << "\n";
        std::cout << "Cổng: " << server->getPort() << "\n";
        std::cout << "Clients kết nối: " << server->getClientCount() << "\n";
        std::cout << "Thời gian hoạt động: " << server->getUptime() << "s\n";
        std::cout << "========================\n\n";
    }
    
    void printHelp() {
        std::cout << "\n=== VPN SERVER COMMANDS ===\n";
        std::cout << "start [port]  - Khởi động server (mặc định port 1194)\n";
        std::cout << "stop          - Dừng server\n";
        std::cout << "status        - Hiển thị trạng thái server\n";
        std::cout << "clients       - Liệt kê clients đang kết nối (với VPN IP)\n";
        std::cout << "vpnstats      - Thống kê VPN và IP pool\n";
        std::cout << "tunstats      - Thống kê interface TUN\n";
        std::cout << "packetstats   - Thống kê packet processing\n";
        std::cout << "kick <id>     - Ngắt kết nối client theo ID\n";
        std::cout << "broadcast <msg> - Gửi tin nhắn đến tất cả clients\n";
        std::cout << "help          - Hiển thị trợ giúp\n";
        std::cout << "clear         - Xóa màn hình\n";
        std::cout << "quit/exit     - Thoát chương trình\n";
        std::cout << "============================\n\n";
    }
    
    void listClients() {
        if (!server) {
            std::cout << "[WARN] Server chưa khởi động\n";
            return;
        }
        
        auto clients = server->getConnectedClients();
        if (clients.empty()) {
            std::cout << "Không có client nào đang kết nối\n";
            return;
        }
        
        std::cout << "\n=== CONNECTED CLIENTS ===\n";
        std::cout << std::left 
                  << std::setw(5) << "ID" 
                  << std::setw(18) << "Real IP" 
                  << std::setw(18) << "VPN IP"
                  << std::setw(16) << "Connect Time"
                  << std::setw(15) << "Username"
                  << std::setw(12) << "Bytes Sent"
                  << std::setw(12) << "Bytes Recv"
                  << std::setw(10) << "Status\n";
        std::cout << std::string(110, '-') << "\n";
        
        for (const auto& client : clients) {
            std::string vpnIP = client.ipAssigned ? client.assignedVpnIP : "Not assigned";
            std::string username = client.authenticated ? client.username : "Not auth";
            
            std::cout << std::left 
                      << std::setw(5) << client.id
                      << std::setw(18) << client.realIP
                      << std::setw(18) << vpnIP
                      << std::setw(16) << client.connectTime
                      << std::setw(15) << username
                      << std::setw(12) << client.bytesSent
                      << std::setw(12) << client.bytesReceived
                      << std::setw(10) << (client.authenticated ? "Active" : "Pending") << "\n";
        }
        std::cout << "==========================\n\n";
    }
    
    void showPacketStats() {
        if (!server) {
            std::cout << "[WARN] Server chưa khởi động\n";
            return;
        }
        
        std::cout << "\n=== PACKET STATISTICS ===\n";
        auto tun = server->getTUNInterface();
        if (tun) {
            std::cout << "TUN Interface: " << tun->getName() << "\n";
            std::cout << "Bytes Received (from TUN): " << tun->getBytesReceived() << "\n";
            std::cout << "Bytes Sent (to TUN): " << tun->getBytesSent() << "\n";
        }
        
        PacketStats stats = server->getPacketHandler()->getPacketStats();
        std::cout << "Total Packets: " << stats.totalPackets << "\n";
        std::cout << "Total Bytes: " << stats.totalBytes << "\n";
        std::cout << "Packets to Clients: " << stats.packetsToClients << " (" << stats.bytesToClients << " bytes)\n";
        std::cout << "Packets from Clients: " << stats.packetsFromClients << " (" << stats.bytesFromClients << " bytes)\n";
        std::cout << "Packets to Internet: " << stats.packetsToInternet << " (" << stats.bytesToInternet << " bytes)\n";
        std::cout << "========================\n\n";
    }
    
    VPNServer* getServer() { 
        return server.get(); 
    }
    
    bool isRunning() const { 
        return running; 
    }
};

std::unique_ptr<VPNServerManager> g_serverManager;
std::atomic<bool> g_running{true};

void signalHandler(int signal) {
    std::cout << "\n[INFO] Nhận tín hiệu dừng (" << signal << "). Đang thoát...\n";
    g_running = false;
    
    if (g_serverManager) {
        g_serverManager->stop();
    }
}

void setupSignalHandlers() {
    signal(SIGINT, signalHandler);
    #ifndef _WIN32
    signal(SIGTERM, signalHandler);
    signal(SIGQUIT, signalHandler);
    #endif
}

bool initializeNetworking() {
    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "[ERROR] Không thể khởi tạo Winsock\n";
        return false;
    }
    #endif
    return true;
}

void cleanupNetworking() {
    #ifdef _WIN32
    WSACleanup();
    #endif
}

void printBanner() {
    std::cout << "=====================================\n";
    std::cout << "    VPN SERVER CONTROL PANEL        \n";
    std::cout << "=====================================\n";
    std::cout << "Phiên bản: 2.0.0\n";
    std::cout << "Giao thức: Custom VPN Protocol\n";
    std::cout << "Hỗ trợ: Linux x64, TUN/TAP\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n\n";
}

int main() {
    try {
        setupSignalHandlers();
        
        if (!initializeNetworking()) {
            return 1;
        }
        
        printBanner();
        
        g_serverManager = std::unique_ptr<VPNServerManager>(new VPNServerManager());
        g_serverManager->printHelp();
        
        std::string command;
        while (g_running) {
            std::cout << "vpn-server> ";
            if (!std::getline(std::cin, command)) {
                break;
            }
            
            if (command.empty()) continue;
            
            std::istringstream iss(command);
            std::string cmd;
            iss >> cmd;
            
            try {
                if (cmd == "start") {
                    int port = 1194;
                    if (iss >> port && (port < 1 || port > 65535)) {
                        std::cout << "[ERROR] Port phải trong khoảng 1-65535\n";
                        continue;
                    }
                    g_serverManager->start(port);
                }
                else if (cmd == "stop") {
                    g_serverManager->stop();
                }
                else if (cmd == "status") {
                    g_serverManager->printStatus();
                }
                else if (cmd == "clients") {
                    g_serverManager->listClients();
                }
                else if (cmd == "kick") {
                    int clientId;
                    if (iss >> clientId) {
                        if (g_serverManager->getServer()) {
                            if (g_serverManager->getServer()->disconnectClient(clientId)) {
                                std::cout << "[INFO] Đã ngắt kết nối client " << clientId << "\n";
                            } else {
                                std::cout << "[WARN] Không tìm thấy client " << clientId << "\n";
                            }
                        } else {
                            std::cout << "[WARN] Server chưa khởi động\n";
                        }
                    } else {
                        std::cout << "[ERROR] Sử dụng: kick <client_id>\n";
                    }
                }
                else if (cmd == "broadcast") {
                    std::string message;
                    std::getline(iss, message);
                    if (!message.empty()) {
                        message = message.substr(1);
                        std::cout << "[INFO] Broadcasting: " << message << "\n";
                        if (g_serverManager->getServer()) {
                            g_serverManager->getServer()->getClientManager()->broadcastToClients("BROADCAST|" + message + "\n");
                        } else {
                            std::cout << "[WARN] Server chưa khởi động\n";
                        }
                    } else {
                        std::cout << "[ERROR] Sử dụng: broadcast <message>\n";
                    }
                }
                else if (cmd == "vpnstats") {
                    if (g_serverManager->getServer()) {
                        auto stats = g_serverManager->getServer()->getVPNStats();
                        std::cout << "\n";
                        for (const auto& stat : stats) {
                            std::cout << stat << "\n";
                        }
                        std::cout << "\n";
                    } else {
                        std::cout << "[WARN] Server chưa khởi động\n";
                    }
                }
                else if (cmd == "tunstats") {
                    if (g_serverManager->getServer()) {
                        auto tun = g_serverManager->getServer()->getTUNInterface();
                        if (tun) {
                            std::cout << "\n=== TUN INTERFACE STATUS ===\n";
                            std::cout << "Tên interface: " << tun->getName() << "\n";
                            std::cout << "IP: " << tun->getIP() << "/" << tun->getMask() << "\n";
                            std::cout << "Bytes nhận: " << tun->getBytesReceived() << "\n";
                            std::cout << "Bytes gửi: " << tun->getBytesSent() << "\n";
                            std::cout << "Trạng thái: " << (tun->isOpened() ? "OPEN" : "CLOSED") << "\n";
                            std::cout << "=============================\n\n";
                        } else {
                            std::cout << "[WARN] TUN interface chưa được khởi tạo\n";
                        }
                    } else {
                        std::cout << "[WARN] Server chưa khởi động\n";
                    }
                }
                else if (cmd == "packetstats") {
                    g_serverManager->showPacketStats();
                }
                else if (cmd == "clear") {
                    system("clear || cls");
                    printBanner();
                }
                else if (cmd == "help") {
                    g_serverManager->printHelp();
                }
                else if (cmd == "quit" || cmd == "exit") {
                    g_running = false;
                }
                else {
                    std::cout << "[ERROR] Lệnh không hợp lệ: '" << cmd << "'\n";
                    std::cout << "[INFO] Gõ 'help' để xem danh sách lệnh.\n";
                }
            } catch (const std::exception& e) {
                std::cout << "[ERROR] Exception khi thực hiện lệnh: " << e.what() << "\n";
            }
        }
        
        std::cout << "[INFO] Đang dọn dẹp...\n";
        g_serverManager->stop();
        g_serverManager.reset();
        
    } catch (const std::exception& e) {
        std::cout << "[FATAL] Unhandled exception: " << e.what() << "\n";
        cleanupNetworking();
        return 1;
    }
    
    cleanupNetworking();
    std::cout << "[INFO] Chương trình đã thoát an toàn.\n";
    return 0;
}