#include <iostream>
#include <thread>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <signal.h>

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

#include "src/core/vpn_server.h"
#include "src/network/socket_manager.h"

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
        std::cout << "clients       - Liệt kê clients đang kết nối\n";
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
                  << std::setw(16) << "IP Address" 
                  << std::setw(12) << "Connect Time"
                  << std::setw(10) << "Status\n";
        std::cout << std::string(45, '-') << "\n";

        for (const auto& client : clients) {
            std::cout << std::left << std::setw(5) << client.id
                      << std::setw(16) << client.ip
                      << std::setw(12) << client.connectTime
                      << std::setw(10) << "Active\n";
        }
        std::cout << "=========================\n\n";
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
    std::cout << "Phiên bản: 1.0.0\n";
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
