#include "tun_interface.h"
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <net/if.h>
#include <cstring>
//#include <iostream>
#include <sstream>
#include <cstdlib>
#include <fstream>


// Một số SDK/macOS không định nghĩa SYSPROTO_CONTROL → tự define
#ifndef SYSPROTO_CONTROL
#define SYSPROTO_CONTROL 2
#endif

TUNInterface::TUNInterface(const std::string& name)
    : interfaceName(name), isOpen(false), tunFd(-1),
    vpnIP(""), subnetMask(""), serverIP(""),
    bytesReceived(0), bytesSent(0) {}

TUNInterface::~TUNInterface() {
    close();
}

bool TUNInterface::create() {
    if (isOpen.load()) return true;

    struct ctl_info ctlInfo;
    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strncpy(ctlInfo.ctl_name, "com.apple.net.utun_control", sizeof(ctlInfo.ctl_name));

    tunFd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (tunFd < 0) {
        perror("socket");
        return false;
    }

    if (ioctl(tunFd, CTLIOCGINFO, &ctlInfo) < 0) {
        perror("ioctl(CTLIOCGINFO)");
        ::close(tunFd);
        return false;
    }

    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_unit = 0; // 0 = để kernel chọn utunX

    if (connect(tunFd, (struct sockaddr*)&sc, sizeof(sc)) < 0) {
        perror("connect");
        ::close(tunFd);
        return false;
    }

    // Lấy tên interface thực tế (utun0, utun1, …)
    char ifname[20];
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(tunFd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == 0) {
        interfaceName = ifname;
    } else {
        interfaceName = "utun0"; // fallback
    }

    // non-blocking
    fcntl(tunFd, F_SETFL, O_NONBLOCK);

    isOpen.store(true);
    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask,
                             const std::string& server) {
    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;

    return configureClientMode();
}

bool TUNInterface::configureClientMode() {
    if (!isOpen.load()) return false;

    // 1. Cấu hình IP với peer point-to-point
    std::ostringstream cmd;
    cmd << "ifconfig " << interfaceName << " " << vpnIP
        << " 10.8.0.1 netmask 255.255.255.0 up";
    if (!executeCommand(cmd.str())) return false;

    // 2. Thêm route cho toàn bộ subnet VPN
    std::ostringstream subnetRouteCmd;
    subnetRouteCmd << "route add -net 10.8.0.0/24 -interface " << interfaceName;
    executeCommand(subnetRouteCmd.str());

    // 3. **QUAN TRỌNG**: Thêm default route qua VPN
    // Điều này khiến tất cả traffic đi qua VPN
    std::ostringstream defaultRouteCmd;
    defaultRouteCmd << "route add default -interface " << interfaceName;
    executeCommand(defaultRouteCmd.str());

    // 4. Lưu gateway cũ và thêm route cho server IP
    if (!serverIP.empty()) {
        std::string oldGateway = getDefaultGateway();
        if (!oldGateway.empty()) {
            // Lưu gateway để restore sau
            std::ostringstream saveCmd;
            saveCmd << "echo " << oldGateway << " > /tmp/vpn_old_gateway";
            executeCommand(saveCmd.str());

            // Route cho server qua gateway cũ (để duy trì kết nối VPN)
            std::ostringstream serverRouteCmd;
            serverRouteCmd << "route add -host " << serverIP << " " << oldGateway;
            executeCommand(serverRouteCmd.str());
        }
    }

    // 5. Cấu hình DNS (optional - giúp resolve domain names)
    executeCommand("networksetup -setdnsservers Wi-Fi 8.8.8.8 8.8.4.4");

    std::cout << "[INFO] Client mode configured with default route via VPN\n";
    return true;
}

bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
    vpnIP = ip;
    subnetMask = mask;
    std::ostringstream cmd;
    cmd << "ifconfig " << interfaceName << " " << vpnIP << " netmask " << subnetMask << " up";
    return executeCommand(cmd.str());
}

bool TUNInterface::setRoutes() {
    if (serverIP.empty()) return true; // không có serverIP thì bỏ qua
    std::ostringstream cmd;
    cmd << "route add default " << vpnIP;
    return executeCommand(cmd.str());
}

// std::string TUNInterface::getDefaultGateway() {
//     // macOS: có thể đọc từ "route -n get default"
//     // Ở đây tạm stub để tránh lỗi linker
//     return "";
// }


// bool TUNInterface::configureClientMode() {
//     if (!isOpen.load()) return false;

//     // 1. Cấu hình IP với peer point-to-point
//     std::ostringstream cmd;
//     cmd << "ifconfig " << interfaceName << " " << vpnIP
//         << " 10.8.0.1 netmask 255.255.255.0 up";
//     if (!executeCommand(cmd.str())) return false;

//     // 2. Lưu default gateway cũ TRƯỚC KHI thay đổi
//     std::string oldGateway = getDefaultGateway();
//     if (!oldGateway.empty()) {
//         std::ostringstream saveCmd;
//         saveCmd << "echo " << oldGateway << " > /tmp/vpn_old_gateway";
//         executeCommand(saveCmd.str());

//         std::cout << "[INFO] Saved old gateway: " << oldGateway << "\n";
//     }

//     // 3. Thêm route cho server IP qua gateway cũ (để duy trì kết nối VPN)
//     if (!serverIP.empty() && !oldGateway.empty()) {
//         std::ostringstream serverRouteCmd;
//         serverRouteCmd << "route add -host " << serverIP << " " << oldGateway;
//         executeCommand(serverRouteCmd.str());
//         std::cout << "[INFO] Added route for VPN server via old gateway\n";
//     }

//     // 4. Thêm route cho subnet VPN
//     std::ostringstream subnetRouteCmd;
//     subnetRouteCmd << "route add -net 10.8.0.0/24 -interface " << interfaceName;
//     executeCommand(subnetRouteCmd.str());

//     // 5. *QUAN TRỌNG*: Thay đổi default route qua VPN gateway (10.8.0.1)
//     // Xóa default route cũ
//     executeCommand("route delete default");

//     // Thêm default route mới qua VPN gateway
//     std::ostringstream newDefaultRoute;
//     newDefaultRoute << "route add default 10.8.0.1";
//     if (!executeCommand(newDefaultRoute.str())) {
//         std::cout << "[ERROR] Failed to add default route via VPN\n";
//         return false;
//     }

//     std::cout << "[INFO] Client routing configured - all traffic via VPN (10.8.0.1)\n";
//     return true;
// }

std::string TUNInterface::getDefaultGateway() {
    std::string gateway;
    FILE* pipe = popen("route -n get default 2>/dev/null | grep gateway | awk '{print $2}'", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            gateway = buffer;
            // Xóa newline
            gateway.erase(gateway.find_last_not_of(" \n\r\t") + 1);
        }
        pclose(pipe);
    }
    return gateway;
}

std::string TUNInterface::getDefaultInterface() {
    // macOS: có thể đọc từ "route -n get default | grep interface:"
    // Ở đây tạm stub để tránh lỗi linker
    return "en0"; // giả định Wi-Fi
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    int ret = system(cmd.c_str());
    return (ret == 0);
}

// Thay thế hàm readPacket hiện tại bằng hàm này
int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load() || tunFd < 0) return -1;

    // --- BẮT ĐẦU THAY ĐỔI ---
    // Buffer tạm để đọc cả 4 byte header của macOS
    char readBuffer[maxSize + 4];
    int n = ::read(tunFd, readBuffer, sizeof(readBuffer));

    if (n > 4) {
        // Bỏ qua 4 byte header, chỉ sao chép gói tin IP thực sự
        memcpy(buffer, readBuffer + 4, n - 4);
        bytesReceived += (n - 4);
        return n - 4; // Trả về kích thước của gói tin IP
    }

    // Nếu đọc lỗi hoặc không có dữ liệu
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        // Log lỗi nếu cần
    }
    return 0;
    // --- KẾT THÚC THAY ĐỔI ---
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load() || tunFd < 0) return -1;
    if (size <= 0) return 0;

    // --- BẮT ĐẦU THAY ĐỔI ---
    char packetWithHeader[size + 4];

    // Tạo header AF_INET (IPv4) cho macOS
    uint32_t header = htonl(AF_INET);
    memcpy(packetWithHeader, &header, 4);

    // Gắn gói tin IP vào sau header
    memcpy(packetWithHeader + 4, buffer, size);

    // Ghi toàn bộ (header + packet) vào utun
    int n = ::write(tunFd, packetWithHeader, size + 4);

    if (n > 4) {
        bytesSent += (n - 4);
        return n - 4; // Trả về kích thước của gói tin IP đã gửi
    }

    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        // Log lỗi nếu cần
    }
    return 0;
    // --- KẾT THÚC THAY ĐỔI ---
}

void TUNInterface::close() {
    if (isOpen.load() && tunFd >= 0) {
        // Restore default gateway
        std::string oldGateway;
        std::ifstream gw("/tmp/vpn_old_gateway");
        if (gw.is_open()) {
            std::getline(gw, oldGateway);
            gw.close();
            if (!oldGateway.empty()) {
                std::ostringstream restoreCmd;
                restoreCmd << "route add default " << oldGateway;
                executeCommand(restoreCmd.str());
            }
            executeCommand("rm /tmp/vpn_old_gateway");
        }

        // Remove VPN routes
        executeCommand("route delete -net 10.8.0.0/24 2>/dev/null");
        executeCommand("route delete default -interface " + interfaceName + " 2>/dev/null");

        ::close(tunFd);
        tunFd = -1;
        isOpen.store(false);
    }
}

void TUNInterface::resetStats() {
    bytesReceived = 0;
    bytesSent = 0;
}
