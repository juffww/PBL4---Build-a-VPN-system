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
            std::cout << "[ERROR] VPN Server requires root privileges\n";
            std::cout << "[INFO] Please run with: sudo ./vpn_server\n";
            return false;
        }
        
        if (system("lsmod | grep -q '^tun '") != 0) {
            std::cout << "[WARN] TUN module not loaded. Attempting to load...\n";
            if (system("modprobe tun") != 0) {
                std::cout << "[ERROR] Failed to load TUN module\n";
                return false;
            }
            std::cout << "[INFO] TUN module loaded\n";
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
            std::cout << "[WARN] Server is already running\n";
            return;
        }
        
        if (!checkSystemRequirements()) {
            return;
        }
        
        try {
            server = std::unique_ptr<VPNServer>(new VPNServer(port));
            
            std::cout << "[INFO] Initializing VPN Server...\n";
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
                
                std::cout << "[INFO] VPN Server started on port " << port << "\n";
                std::cout << "[INFO] Server IP: " << server->getServerIP() << "\n";
                printStatus();
            } else {
                std::cout << "[ERROR] Failed to start server\n";
                server.reset();
            }
        } catch (const std::exception& e) {
            std::cout << "[ERROR] Exception during server creation: " << e.what() << "\n";
            server.reset();
        }
    }
    
    void stop() {
        if (running && server) {
            std::cout << "[INFO] Stopping server...\n";
            running = false;
            
            server->stop();
            
            if (serverThread.joinable()) {
                serverThread.join();
            }
            
            server.reset();
            std::cout << "[INFO] Server stopped\n";
        }
    }
    
    void printStatus() {
        if (!server) {
            std::cout << "[WARN] Server not started\n";
            return;
        }
        
        std::cout << "\n=== VPN SERVER STATUS ===\n";
        std::cout << "Status: " << (running ? "RUNNING" : "STOPPED") << "\n";
        std::cout << "Port: " << server->getPort() << "\n";
        std::cout << "Connected Clients: " << server->getClientCount() << "\n";
        std::cout << "Uptime: " << server->getUptime() << "s\n";
        std::cout << "=========================\n\n";
    }
    
    void printHelp() {
        std::cout << "\n=== VPN SERVER COMMANDS ===\n";
        std::cout << "start [port]  - Start server (default port 1194)\n";
        std::cout << "stop          - Stop server\n";
        std::cout << "clients       - List connected clients\n";
        std::cout << "help          - Show help\n";
        std::cout << "clear         - Clear screen\n";
        std::cout << "quit/exit     - Exit program\n";
        std::cout << "===========================\n\n";
    }
    
    void listClients() {
        if (!server) {
            std::cout << "[WARN] Server not started\n";
            return;
        }
        
        auto clients = server->getConnectedClients();
        if (clients.empty()) {
            std::cout << "No clients connected\n";
            return;
        }
        
        std::cout << "\n=== CONNECTED CLIENTS ===\n";
        std::cout << std::left 
                  << std::setw(5) << "ID" 
                  << std::setw(18) << "Real IP" 
                  << std::setw(18) << "VPN IP"
                  << std::setw(16) << "Username"
                  << std::setw(12) << "Bytes Sent"
                  << std::setw(12) << "Bytes Recv"
                  << std::setw(10) << "Status\n";
        std::cout << std::string(95, '-') << "\n";
        
        for (const auto& client : clients) {
            std::string vpnIP = client.ipAssigned ? client.assignedVpnIP : "Not assigned";
            std::string username = client.authenticated ? client.username : "Not auth";
            
            std::cout << std::left 
                      << std::setw(5) << client.id
                      << std::setw(18) << client.realIP
                      << std::setw(18) << vpnIP
                      << std::setw(16) << username
                      << std::setw(12) << client.bytesSent
                      << std::setw(12) << client.bytesReceived
                      << std::setw(10) << (client.authenticated ? "Active" : "Pending") << "\n";
        }
        std::cout << "==========================\n\n";
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
    std::cout << "\n[INFO] Received stop signal (" << signal << "). Exiting...\n";
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
        std::cout << "[ERROR] Failed to initialize Winsock\n";
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
    std::cout << "Version: 2.0.0\n";
    std::cout << "Protocol: Custom VPN Protocol\n";
    std::cout << "Support: Linux x64, TUN/TAP\n";
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
                        std::cout << "[ERROR] Port must be between 1-65535\n";
                        continue;
                    }
                    g_serverManager->start(port);
                }
                else if (cmd == "stop") {
                    g_serverManager->stop();
                }
                else if (cmd == "clients") {
                    g_serverManager->listClients();
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
                    std::cout << "[ERROR] Unknown command: '" << cmd << "'\n";
                    std::cout << "[INFO] Type 'help' to see available commands\n";
                }
            } catch (const std::exception& e) {
                std::cout << "[ERROR] Exception while executing command: " << e.what() << "\n";
            }
        }
        
        std::cout << "[INFO] Cleaning up...\n";
        g_serverManager->stop();
        g_serverManager.reset();
        
    } catch (const std::exception& e) {
        std::cout << "[FATAL] Unhandled exception: " << e.what() << "\n";
        cleanupNetworking();
        return 1;
    }
    
    cleanupNetworking();
    std::cout << "[INFO] Program exited safely\n";
    return 0;
}