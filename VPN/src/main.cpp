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
    #include <sys/stat.h>
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
    std::string certFile;
    std::string keyFile;
    
    bool checkSystemRequirements() {
        #ifndef _WIN32
        if (getuid() != 0) {
            std::cout << "[ERROR] VPN Server requires root privileges\n";
            std::cout << "[INFO] Please run with: sudo ./vpn_server --cert <cert> --key <key>\n";
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
    
    bool checkCertificates() {
        if (certFile.empty() || keyFile.empty()) {
            std::cout << "[ERROR] TLS certificate and key required!\n";
            std::cout << "[INFO] Usage: ./vpn_server --cert <cert_file> --key <key_file>\n";
            std::cout << "[INFO] Generate certs: ./generate_certificates.sh\n";
            return false;
        }
        
        #ifndef _WIN32
        // Check if certificate file exists
        struct stat certStat;
        if (stat(certFile.c_str(), &certStat) != 0) {
            std::cout << "[ERROR] Certificate file not found: " << certFile << "\n";
            return false;
        }
        
        // Check if key file exists
        struct stat keyStat;
        if (stat(keyFile.c_str(), &keyStat) != 0) {
            std::cout << "[ERROR] Private key file not found: " << keyFile << "\n";
            return false;
        }
        
        // Check key file permissions (should be 600)
        if ((keyStat.st_mode & 0777) != 0600) {
            std::cout << "[WARN] Private key has insecure permissions!\n";
            std::cout << "[INFO] Recommended: chmod 600 " << keyFile << "\n";
        }
        #endif
        
        std::cout << "[TLS] Certificate: " << certFile << "\n";
        std::cout << "[TLS] Private Key: " << keyFile << "\n";
        
        return true;
    }

public:
    VPNServerManager() : server(nullptr), running(false) {}
    
    ~VPNServerManager() { 
        stop(); 
    }
    
    void setCertificates(const std::string& cert, const std::string& key) {
        certFile = cert;
        keyFile = key;
    }
    
    void start(int port = 5000) {
        if (running) {
            std::cout << "[WARN] Server is already running\n";
            return;
        }
        
        if (!checkSystemRequirements()) {
            return;
        }
        
        if (!checkCertificates()) {
            return;
        }
        
        try {
            // Create server with TLS support
            server = std::unique_ptr<VPNServer>(new VPNServer(port, certFile, keyFile));
            
            std::cout << "[INFO] Initializing VPN Server with TLS...\n";
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
                std::cout << "[TLS] Secure control channel enabled\n";
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
        std::cout << "Port: " << server->getPort() << " (TLS)\n";
        std::cout << "Connected Clients: " << server->getClientCount() << "\n";
        std::cout << "Uptime: " << server->getUptime() << "s\n";
        std::cout << "=========================\n\n";
    }
    
    void printHelp() {
        std::cout << "\n=== VPN SERVER COMMANDS ===\n";
        std::cout << "start [port]  - Start server (default port 5000)\n";
        std::cout << "stop          - Stop server\n";
        std::cout << "status        - Show server status\n";
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
    std::cout << "╔════════════════════════════════════════════╗\n";
    std::cout << "║       VPN SERVER 2.0 - TLS EDITION         ║\n";
    std::cout << "╚════════════════════════════════════════════╝\n";
    std::cout << "Version: 2.0.0 (TLS Enabled)\n";
    std::cout << "Protocol: TLS + AES-256-GCM\n";
    std::cout << "Support: Linux x64, TUN/TAP\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n\n";
}

void printUsage(const char* programName) {
    std::cout << "\nUsage: " << programName << " [options]\n\n";
    std::cout << "Required options:\n";
    std::cout << "  --cert <file>       TLS certificate file (PEM format)\n";
    std::cout << "  --key <file>        TLS private key file (PEM format)\n\n";
    std::cout << "Optional:\n";
    std::cout << "  --port <port>       Server port (default: 5000)\n";
    std::cout << "  --auto-start        Start server immediately\n";
    std::cout << "  --help              Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  # Interactive mode\n";
    std::cout << "  sudo " << programName << " --cert certs/server.crt --key certs/server.key\n\n";
    std::cout << "  # Auto-start mode\n";
    std::cout << "  sudo " << programName << " --cert certs/server.crt --key certs/server.key --auto-start\n\n";
    std::cout << "  # Custom port\n";
    std::cout << "  sudo " << programName << " --cert certs/server.crt --key certs/server.key --port 5555\n\n";
    std::cout << "Generate certificates:\n";
    std::cout << "  ./generate_certificates.sh\n\n";
}

int main(int argc, char* argv[]) {
    try {
        setupSignalHandlers();
        
        if (!initializeNetworking()) {
            return 1;
        }
        
        std::string certFile, keyFile;
        int port = 5000;
        bool autoStart = false;
        
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            
            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            }
            else if (arg == "--cert" && i + 1 < argc) {
                certFile = argv[++i];
            }
            else if (arg == "--key" && i + 1 < argc) {
                keyFile = argv[++i];
            }
            else if (arg == "--port" && i + 1 < argc) {
                try {
                    port = std::stoi(argv[++i]);
                    if (port < 1 || port > 65535) {
                        std::cerr << "[ERROR] Port must be between 1-65535\n";
                        return 1;
                    }
                } catch (...) {
                    std::cerr << "[ERROR] Invalid port number\n";
                    return 1;
                }
            }
            else if (arg == "--auto-start") {
                autoStart = true;
            }
            else {
                std::cerr << "[ERROR] Unknown argument: " << arg << "\n";
                printUsage(argv[0]);
                return 1;
            }
        }
        
        // Validate required arguments
        if (certFile.empty() || keyFile.empty()) {
            std::cerr << "[ERROR] Certificate and key files are required!\n\n";
            printUsage(argv[0]);
            return 1;
        }
        
        printBanner();
        
        g_serverManager = std::unique_ptr<VPNServerManager>(new VPNServerManager());
        g_serverManager->setCertificates(certFile, keyFile);
        
        // Auto-start mode
        if (autoStart) {
            std::cout << "[INFO] Auto-start mode enabled\n";
            g_serverManager->start(port);
            
            if (!g_serverManager->isRunning()) {
                std::cerr << "[ERROR] Failed to start server\n";
                cleanupNetworking();
                return 1;
            }
            
            std::cout << "[INFO] Server running. Press Ctrl+C to stop.\n\n";
            
            // Wait for signal
            while (g_running && g_serverManager->isRunning()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        // Interactive mode
        else {
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
                        int customPort = port;
                        if (iss >> customPort) {
                            if (customPort < 1 || customPort > 65535) {
                                std::cout << "[ERROR] Port must be between 1-65535\n";
                                continue;
                            }
                        }
                        g_serverManager->start(customPort);
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