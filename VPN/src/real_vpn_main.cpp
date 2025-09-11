// // real_vpn_main.cpp - Main file for Real VPN Server
// #include <iostream>
// #include <thread>
// #include <vector>
// #include <map>
// #include <string>
// #include <chrono>
// #include <iomanip>
// #include <cstring>
// #include <signal.h>
// #include <unistd.h>

// #include "src/core/real_vpn_server.h"
// #include "src/network/socket_manager.h"

// class RealVPNServerManager {
// private:
//     RealVPNServer* server;
//     bool running;
//     std::thread serverThread;

// public:
//     RealVPNServerManager() : server(nullptr), running(false) {}
    
//     ~RealVPNServerManager() {
//         stop();
//     }

//     void start(int port = 1194) {
//         // Check root privileges
//         if (getuid() != 0) {
//             std::cout << "[ERROR] Real VPN Server requires root privileges for TUN interface!\n";
//             std::cout << "[INFO] Please run with: sudo ./real_vpn_server\n";
//             return;
//         }

//         if (running) {
//             std::cout << "[WARN] Server is already running!\n";
//             return;
//         }

//         server = new RealVPNServer(port);
//         if (server->initialize()) {
//             running = true;
//             serverThread = std::thread([this]() {
//                 server->start();
//             });
            
//             std::cout << "[INFO] Real VPN Server started on port " << port << "\n";
//             std::cout << "[INFO] Server IP: " << server->getServerIP() << "\n";
//             std::cout << "[INFO] TUN interface will be created when first client connects\n";
//             printStatus();
//         } else {
//             std::cout << "[ERROR] Cannot start server!\n";
//             delete server;
//             server = nullptr;
//         }
//     }

//     void stop() {
//         if (running && server) {
//             running = false;
//             server->stop();
//             if (serverThread.joinable()) {
//                 serverThread.join();
//             }
//             delete server;
//             server = nullptr;
//             std::cout << "[INFO] Real VPN Server stopped\n";
//         }
//     }

//     void printStatus() {
//         if (!server) return;
        
//         std::cout << "\n=== REAL VPN SERVER STATUS ===\n";
//         std::cout << "Status: " << (running ? "RUNNING" : "STOPPED") << "\n";
//         std::cout << "Port: " << server->getPort() << "\n";
//         std::cout << "Connected clients: " << server->getClientCount() << "\n";
//         std::cout << "Uptime: " << server->getUptime() << "s\n";
//         std::cout << "==============================\n\n";
//     }

//     void printHelp() {
//         std::cout << "\n=== REAL VPN SERVER COMMANDS ===\n";
//         std::cout << "start [port]  - Start server (default port 1194) - REQUIRES ROOT\n";
//         std::cout << "stop          - Stop server\n";
//         std::cout << "status        - Show server status\n";
//         std::cout << "clients       - List connected clients with VPN IPs\n";
//         std::cout << "stats         - Show packet statistics\n";
//         std::cout << "vpnstats      - Show VPN statistics and IP pool\n";
//         std::cout << "kick <id>     - Disconnect client by ID\n";
//         std::cout << "tun           - Show TUN interface information\n";
//         std::cout << "routes        - Show current routing table\n";
//         std::cout << "iptables      - Show current iptables rules\n";
//         std::cout << "help          - Show help\n";
//         std::cout << "quit/exit     - Exit program\n";
//         std::cout << "===============================\n\n";
//     }

//     void listClients() {
//         if (!server) {
//             std::cout << "[WARN] Server not started\n";
//             return;
//         }

//         auto clients = server->getConnectedClients();
//         if (clients.empty()) {
//             std::cout << "No clients connected\n";
//             return;
//         }

//         std::cout << "\n=== CONNECTED CLIENTS ===\n";
//         std::cout << std::left << std::setw(5) << "ID" 
//                 << std::setw(18) << "Real IP" 
//                 << std::setw(18) << "VPN IP"
//                 << std::setw(16) << "Connect Time"
//                 << std::setw(15) << "Username"
//                 << std::setw(10) << "Status\n";
//         std::cout << std::string(85, '-') << "\n";

//         for (const auto& client : clients) {
//             std::string vpnIP = client.ipAssigned ? client.assignedVpnIP : "Not assigned";
//             std::string username = client.authenticated ? client.username : "Not auth";
            
//             std::cout << std::left << std::setw(5) << client.id
//                     << std::setw(18) << client.realIP
//                     << std::setw(18) << vpnIP
//                     << std::setw(16) << client.connectTime
//                     << std::setw(15) << username
//                     << std::setw(10) << (client.authenticated ? "Active" : "Pending")<< "\n";
//         }
//         std::cout << "==========================\n\n";
//     }

//     void showPacketStats() {
//         if (!server) {
//             std::cout << "[WARN] Server not started\n";
//             return;
//         }

//         auto stats = server->getAllClientStats();
//         if (stats.empty()) {
//             std::cout << "No client statistics available\n";
//             return;
//         }

//         std::cout << "\n=== PACKET STATISTICS ===\n";
//         std::cout << std::left << std::setw(8) << "Client" 
//                 << std::setw(12) << "RX Bytes" 
//                 << std::setw(12) << "TX Bytes"
//                 << std::setw(12) << "RX Packets"
//                 << std::setw(12) << "TX Packets"
//                 << std::setw(20) << "Last Activity\n";
//         std::cout << std::string(80, '-') << "\n";

//         for (const auto& stat : stats) {
//             auto duration = std::chrono::duration_cast<std::chrono::seconds>(
//                 std::chrono::steady_clock::now() - stat.second.lastActivity);
            
//             std::cout << std::left << std::setw(8) << stat.first
//                     << std::setw(12) << stat.second.bytesReceived
//                     << std::setw(12) << stat.second.bytesSent
//                     << std::setw(12) << stat.second.packetsReceived
//                     << std::setw(12) << stat.second.packetsSent
//                     << std::setw(20) << (duration.count() > 0 ? std::to_string(duration.count()) + "s ago" : "Active") << "\n";
//         }
//         std::cout << "==========================\n\n";
//     }

//     void showTunInfo() {
//         std::cout << "\n=== TUN INTERFACE INFO ===\n";
//         system("ip addr show | grep -A 5 vpn_server || echo 'TUN interface not found'");
//         std::cout << "==========================\n\n";
//     }

//     void showRoutes() {
//         std::cout << "\n=== ROUTING TABLE ===\n";
//         system("ip route show");
//         std::cout << "=====================\n\n";
//     }

//     void showIptables() {
//         std::cout << "\n=== IPTABLES RULES (NAT) ===\n";
//         system("iptables -t nat -L -n -v || echo 'Cannot access iptables'");
//         std::cout << "============================\n\n";
//     }

//     RealVPNServer* getServer() { return server; }
//     bool isRunning() const { return running; }
// };

// bool g_running = true;
// RealVPNServerManager* g_serverManager = nullptr;

// void signalHandler(int signal) {
//     std::cout << "\n[INFO] Received stop signal. Shutting down...\n";
//     g_running = false;
//     if (g_serverManager) {
//         g_serverManager->stop();
//     }
// }

// int main() {
//     // Setup signal handlers
//     signal(SIGINT, signalHandler);
//     signal(SIGTERM, signalHandler);

//     std::cout << "===========================================\n";
//     std::cout << "   REAL VPN SERVER WITH TUN INTERFACE    \n";
//     std::cout << "===========================================\n";
//     std::cout << "Version: 2.0.0\n";
//     std::cout << "Protocol: Custom VPN with packet routing\n";
//     std::cout << "Features: TUN interface, NAT, IP forwarding\n\n";

//     // Check if running as root
//     if (getuid() != 0) {
//         std::cout << "[WARNING] This program requires root privileges!\n";
//         std::cout << "[INFO] Please run with: sudo " << __FILE__ << "\n";
//         std::cout << "[INFO] Basic server commands available without root\n\n";
//     }

//     RealVPNServerManager serverManager;
//     g_serverManager = &serverManager;
    
//     serverManager.printHelp();

//     std::string command;
//     while (g_running) {
//         std::cout << "real-vpn> ";
//         if (!std::getline(std::cin, command)) {
//             break;
//         }

//         if (command.empty()) continue;

//         // Parse command
//         std::istringstream iss(command);
//         std::string cmd;
//         iss >> cmd;

//         if (cmd == "start") {
//             int port = 1194;
//             iss >> port;
//             serverManager.start(port);
//         }
//         else if (cmd == "stop") {
//             serverManager.stop();
//         }
//         else if (cmd == "status") {
//             serverManager.printStatus();
//         }   
//         else if (cmd == "clients") {
//             serverManager.listClients();
//         }
//         else if (cmd == "stats") {
//             serverManager.showPacketStats();
//         }
//         else if (cmd == "kick") {
//             int clientId;
//             if (iss >> clientId) {
//                 if (serverManager.getServer()) {
//                     if (serverManager.getServer()->disconnectClient(clientId)) {
//                         std::cout << "[INFO] Disconnected client " << clientId << "\n";
//                     } else {
//                         std::cout << "[WARN] Client " << clientId << " not found\n";
//                     }
//                 } else {
//                     std::cout << "[WARN] Server not started\n";
//                 }
//             } else {
//                 std::cout << "[ERROR] Usage: kick <client_id>\n";
//             }
//         }
//         else if (cmd == "tun") {
//             serverManager.showTunInfo();
//         }
//         else if (cmd == "routes") {
//             serverManager.showRoutes();
//         }
//         else if (cmd == "iptables") {
//             serverManager.showIptables();
//         }
//         else if (cmd == "help") {
//             serverManager.printHelp();
//         }
//         else if (cmd == "quit" || cmd == "exit") {
//             g_running = false;
//         }
//         else if (cmd == "vpnstats") {
//             if (serverManager.getServer()) {
//                 auto stats = serverManager.getServer()->getVPNStats();
//                 std::cout << "\n=== VPN STATISTICS ===\n";
//                 for (const auto& stat : stats) {
//                     std::cout << stat << "\n";
//                 }
                
//                 auto assignedIPs = serverManager.getServer()->getAllAssignedVPNIPs();
//                 std::cout << "Assigned VPN IPs:\n";
//                 for (const auto& ip : assignedIPs) {
//                     std::cout << "  - " << ip << "\n";
//                 }
//                 std::cout << "=====================\n\n";
//             } else {
//                 std::cout << "[WARN] Server not started\n";
//             }
//         }
//         else {
//             std::cout << "[ERROR] Unknown command. Type 'help' for command list.\n";
//         }
//     }

//     serverManager.stop();
//     std::cout << "[INFO] Program exited.\n";
//     return 0;
// }