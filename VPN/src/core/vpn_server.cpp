#include "vpn_server.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sstream>

VPNServer::VPNServer(int port)
    : serverPort(port), serverSocket(INVALID_SOCKET), isRunning(false), shouldStop(false),
      clientManager(new ClientManager()), tunnelManager(nullptr), packetHandler(nullptr),
      startTime(std::chrono::steady_clock::now()) {
}

VPNServer::~VPNServer() {
    stop();
    delete tunnelManager;
    delete packetHandler;
    delete clientManager;
}

bool VPNServer::initialize() {
    packetHandler = new PacketHandler();
    tunnelManager = new TunnelManager("tun0", "10.8.0.1", "255.255.255.0");
    tunnelManager->setClientManager(clientManager);

    if (!tunnelManager->initialize()) {
        std::cerr << "[ERROR] Failed to initialize TunnelManager\n";
        return false;
    }

    if (!initializeServerSocket()) {
        std::cerr << "[ERROR] Failed to initialize server socket\n";
        return false;
    }

    std::cout << "[INFO] VPNServer initialized\n";
    return true;
}

bool VPNServer::initializeServerSocket() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[ERROR] Failed to create socket: " << strerror(errno) << "\n";
        return false;
    }

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "[ERROR] Failed to set socket options: " << strerror(errno) << "\n";
        close(serverSocket);
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(serverPort);

    if (bind(serverSocket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[ERROR] Failed to bind socket: " << strerror(errno) << "\n";
        close(serverSocket);
        return false;
    }

    if (listen(serverSocket, 10) < 0) {
        std::cerr << "[ERROR] Failed to listen on socket: " << strerror(errno) << "\n";
        close(serverSocket);
        return false;
    }

    return true;
}

void VPNServer::start() {
    if (isRunning) return;
    isRunning = true;
    shouldStop = false;
    tunnelManager->start();
    std::cout << "[INFO] VPN Server started on port " << serverPort << "\n";

    std::thread([this]() { acceptConnections(); }).detach();
}

void VPNServer::stop() {
    shouldStop = true;
    isRunning = false;
    if (serverSocket != INVALID_SOCKET) {
        close(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    tunnelManager->stop();
    clientManager->disconnectAllClients();
    cleanup();
    std::cout << "[INFO] VPN Server stopped\n";
}

void VPNServer::acceptConnections() {
    while (isRunning && !shouldStop) {
        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        SOCKET client_fd = accept(serverSocket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd != INVALID_SOCKET) {
            std::cout << "[INFO] New client connection received\n";
            int clientId = clientManager->addClient(client_fd);
            clientThreads.emplace_back([this, clientId]() { handleClient(clientId); });
        }
        usleep(100000); // Ngủ 100ms để tránh CPU overload
    }
}

void VPNServer::handleClient(int clientId) {
    char buffer[1024];
    while (isRunning && !shouldStop) {
        ssize_t bytes = recv(clientManager->getClientSocket(clientId), buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            std::cerr << "[INFO] Client " << clientId << " disconnected\n";
            disconnectClient(clientId);
            break;
        }
        buffer[bytes] = '\0';
        processClientMessage(clientId, std::string(buffer));
    }
}

bool VPNServer::processClientMessage(int clientId, const std::string& message) {
    std::istringstream iss(message);
    std::string command;
    iss >> command;

    if (command == "AUTH") return handleAuthCommand(clientId, iss);
    if (command == "PING") return handlePingCommand(clientId);
    if (command == "STATUS") return handleStatusCommand(clientId);

    std::cerr << "[WARN] Unknown command from client " << clientId << ": " << message << "\n";
    return false;
}

bool VPNServer::handleAuthCommand(int clientId, std::istringstream& iss) {
    std::string username, password;
    iss >> username >> password;
    if (clientManager->authenticateClient(clientId, username, password)) {
        std::cout << "[INFO] Client " << clientId << " authenticated\n";
        return true;
    }
    std::cerr << "[ERROR] Client " << clientId << " authentication failed\n";
    return false;
}

bool VPNServer::handlePingCommand(int clientId) {
    std::string response = "PONG";
    send(clientManager->getClientSocket(clientId), response.c_str(), response.size(), 0);
    return true;
}

bool VPNServer::handleStatusCommand(int clientId) {
    std::vector<std::string> stats = getVPNStats();
    std::string response = "STATUS ";
    for (const auto& stat : stats) {
        response += stat + "\n";
    }
    send(clientManager->getClientSocket(clientId), response.c_str(), response.size(), 0);
    return true;
}

void VPNServer::cleanup() {
    for (auto& thread : clientThreads) {
        if (thread.joinable()) thread.join();
    }
    clientThreads.clear();
}

int VPNServer::getPort() const {
    return serverPort;
}

int VPNServer::getClientCount() const {
    return clientManager->getClientCount();
}

std::string VPNServer::getServerIP() const {
    ifaddrs* ifa;
    std::string ip = "0.0.0.0";
    if (getifaddrs(&ifa) == 0) {
        for (ifaddrs* i = ifa; i != nullptr; i = i->ifa_next) {
            if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET && strcmp(i->ifa_name, "lo") != 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)i->ifa_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
                ip = ip_str;
                break;
            }
        }
        freeifaddrs(ifa);
    }
    return ip;
}

long long VPNServer::getUptime() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - startTime).count();
}

std::vector<ClientInfo> VPNServer::getConnectedClients() const {
    return clientManager->getConnectedClients();
}

bool VPNServer::disconnectClient(int clientId) {
    return clientManager->removeClient(clientId);
}

std::vector<std::string> VPNServer::getAllAssignedVPNIPs() const {
    return clientManager->getAllAssignedVPNIPs();
}

TUNInterface* VPNServer::getTUNInterface() const {
    return tunnelManager ? tunnelManager->getTUNInterface() : nullptr;
}

std::vector<std::string> VPNServer::getVPNStats() {
    std::vector<std::string> stats;
    TUNInterface* tun = tunnelManager->getTUNInterface();
    if (tun) {
        stats.push_back("Interface: " + tun->getInterfaceName());
        stats.push_back("IP: " + tun->getIP() + "/" + tun->getMask());
        stats.push_back("Bytes Received: " + std::to_string(tun->getBytesReceived()));
        stats.push_back("Bytes Sent: " + std::to_string(tun->getBytesSent()));
        stats.push_back("Status: " + std::string(tun->isOpened() ? "OPEN" : "CLOSED"));
    }
    return stats;
}

ClientManager* VPNServer::getClientManager() const {
    return clientManager;
}

PacketHandler* VPNServer::getPacketHandler() const {
    return packetHandler;
}