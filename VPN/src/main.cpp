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
#include "network/socket_manager.h"

//Giao diện điều khiển server
class VPNServerManager {
private:
    VPNServer* server;
    bool running;
    std::thread serverThread;

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

        server = new VPNServer(port);
        if (server->initialize()) {
            running = true;
            serverThread = std::thread([this]() {
                server->start();
            });
            
            std::cout << "[INFO] VPN Server đã khởi động trên cổng " << port << "\n";
            std::cout << "[INFO] Server IP: " << server->getServerIP() << "\n";
            printStatus();
        } else {
            std::cout << "[ERROR] Không thể khởi động server!\n";
            delete server;
            server = nullptr;
        }
    }

    void stop() {
        if (running && server) {
            running = false;
            server->stop();
            if (serverThread.joinable()) {
                serverThread.join();
            }
            delete server;
            server = nullptr;
            std::cout << "[INFO] Server đã dừng\n";
        }
    }

    void printStatus() {
        if (!server) return;
        
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
        std::cout << "kick <id>     - Ngắt kết nối client theo ID\n";
        std::cout << "help          - Hiển thị trợ giúp\n";
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
        std::cout << std::left << std::setw(5) << "ID" 
                << std::setw(18) << "Real IP" 
                << std::setw(18) << "VPN IP"
                << std::setw(16) << "Connect Time"
                << std::setw(15) << "Username"
                << std::setw(10) << "Status\n";
        std::cout << std::string(85, '-') << "\n";

        for (const auto& client : clients) {
            std::string vpnIP = client.ipAssigned ? client.assignedVpnIP : "Not assigned";
            std::string username = client.authenticated ? client.username : "Not auth";
            
            std::cout << std::left << std::setw(5) << client.id
                    << std::setw(18) << client.realIP
                    << std::setw(18) << vpnIP
                    << std::setw(16) << client.connectTime
                    << std::setw(15) << username
                    << std::setw(10) << (client.authenticated ? "Active" : "Pending")<< "\n";
        }
        std::cout << "===========================\n\n";
    }

    VPNServer* getServer() { return server; }
    bool isRunning() const { return running; }
};

bool g_running = true;
VPNServerManager* g_serverManager = nullptr;

void signalHandler(int signal) {
    std::cout << "\n[INFO] Nhận tín hiệu dừng. Đang thoát...\n";
    g_running = false;
    if (g_serverManager) {
        g_serverManager->stop();
    }
}

int main() {
    // Thiết lập xử lý tín hiệu
    signal(SIGINT, signalHandler);
    #ifndef _WIN32
    signal(SIGTERM, signalHandler);
    #endif

    // Khởi tạo Winsock trên Windows
    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "[ERROR] Không thể khởi tạo Winsock\n";
        return 1;
    }
    #endif

    std::cout << "=================================\n";
    std::cout << "   VPN SERVER CONTROL PANEL     \n";
    std::cout << "=================================\n";
    std::cout << "Phiên bản: 3.0.0\n";
    std::cout << "Giao thức: OpenVPN Compatible\n\n";

    VPNServerManager serverManager;
    g_serverManager = &serverManager;
    
    serverManager.printHelp();

    std::string command;
    while (g_running) {
        std::cout << "vpn-server> ";
        if (!std::getline(std::cin, command)) {
            break;
        }

        if (command.empty()) continue;

        // Parse command
        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;

        if (cmd == "start") {
            int port = 1194;
            iss >> port;
            serverManager.start(port);
        }
        else if (cmd == "stop") {
            serverManager.stop();
        }
        else if (cmd == "status") {
            serverManager.printStatus();
        }   
        else if (cmd == "clients") {
            serverManager.listClients();
        }
        else if (cmd == "kick") {
            int clientId;
            if (iss >> clientId) {
                if (serverManager.getServer()) {
                    if (serverManager.getServer()->disconnectClient(clientId)) {
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
        else if (cmd == "help") {
            serverManager.printHelp();
        }
        else if (cmd == "quit" || cmd == "exit") {
            g_running = false;
        }
        else if (cmd == "vpnstats") {
            if (serverManager.getServer()) {
                auto stats = serverManager.getServer()->getVPNStats();
                std::cout << "\n=== VPN STATISTICS ===\n";
                for (const auto& stat : stats) {
                    std::cout << stat << "\n";
                }
                
                // Hiển thị danh sách IP đã cấp phát
                auto assignedIPs = serverManager.getServer()->getAllAssignedVPNIPs();
                std::cout << "Assigned VPN IPs:\n";
                for (const auto& ip : assignedIPs) {
                    std::cout << "  - " << ip << "\n";
                }
                std::cout << "=====================\n\n";
            } else {
                std::cout << "[WARN] Server chưa khởi động\n";
            }
        }
        else if (cmd == "tunstats") {
            if (serverManager.getServer()) {
                auto tun = serverManager.getServer()->getTUNInterface();
                if (tun) {
                    std::cout << "\n=== TUN INTERFACE STATUS ===\n";
                    std::cout << "Tên interface: " << tun->getName() << "\n";
                    std::cout << "IP: " << tun->getIP() << "/" << tun->getMask() << "\n";
                    std::cout << "Bytes nhận: " << tun->getBytesReceived() << "\n";
                    std::cout << "Bytes gửi: " << tun->getBytesSent() << "\n";
                    std::cout << "Trạng thái: " << (tun->isOpened() ? "OPEN" : "CLOSED") << "\n";
                    std::cout << "=============================\n\n";
                } else {
                    std::cout << "[WARN] Server chưa khởi tạo TUN interface\n";
                }
            } else {
                std::cout << "[WARN] Server chưa chạy\n";
            }
        }
        else {
            std::cout << "[ERROR] Lệnh không hợp lệ. Gõ 'help' để xem danh sách lệnh.\n";
        }
    }

    serverManager.stop();
    
    #ifdef _WIN32
    WSACleanup();
    #endif

    std::cout << "[INFO] Chương trình đã thoát.\n";
    return 0;
}