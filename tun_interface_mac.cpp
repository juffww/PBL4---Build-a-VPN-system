#include "tun_interface.h"
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <net/if.h>
#include <cstring>
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <arpa/inet.h>
#include <vector>

#ifndef SYSPROTO_CONTROL
#define SYSPROTO_CONTROL 2
#endif

// Helper: Thực thi lệnh và log
bool runCmd(const std::string& cmd) {
    std::cout << "[CMD] " << cmd << std::endl;
    return (system(cmd.c_str()) == 0);
}

TUNInterface::TUNInterface(const std::string& name)
    : interfaceName(name), isOpen(false), tunFd(-1),
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
    sc.sc_unit = 0; // Kernel tự chọn utunX

    if (connect(tunFd, (struct sockaddr*)&sc, sizeof(sc)) < 0) {
        perror("connect");
        ::close(tunFd);
        return false;
    }

    char ifname[20];
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(tunFd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == 0) {
        interfaceName = ifname;
    } else {
        // Fallback: đoán tên dựa trên ID? Rủi ro, nhưng thường là utun0/1
        // Tốt nhất là in lỗi nếu không lấy được tên
        std::cerr << "[TUN] Warning: Could not get interface name, assuming " << interfaceName << std::endl;
    }

    fcntl(tunFd, F_SETFL, O_NONBLOCK);
    isOpen.store(true);

    std::cout << "[TUN] Created interface: " << interfaceName << std::endl;
    return true;
}

std::string TUNInterface::getDefaultGateway() {
    // macOS: parse từ "route -n get default"
    FILE* pipe = popen("route -n get default | grep gateway | awk '{print $2}'", "r");
    if (!pipe) return "";
    char buffer[128];
    std::string result = "";
    if (fgets(buffer, 128, pipe) != NULL) {
        result = buffer;
        result.erase(result.find_last_not_of(" \n\r\t") + 1);
    }
    pclose(pipe);
    return result;
}

bool TUNInterface::configureClientMode() {
    if (!isOpen.load()) return false;

    std::string oldGateway = getDefaultGateway();
    if (oldGateway.empty()) {
        std::cerr << "[TUN] Error: No physical gateway found!\n";
        // Vẫn tiếp tục thử, có thể đang trong mạng LAN đặc biệt
    } else {
        std::cout << "[TUN] Physical Gateway: " << oldGateway << std::endl;

        // Route tới Server thật qua cổng vật lý để tránh loop VPN
        if (!serverIP.empty()) {
            runCmd("route delete " + serverIP + " >/dev/null 2>&1");
            runCmd("route add " + serverIP + " " + oldGateway);
        }
    }

    // Cấu hình IP cho interface
    std::ostringstream ipCmd;
    ipCmd << "ifconfig " << interfaceName << " " << vpnIP << " " << vpnIP << " netmask 255.255.255.0 up";
    // Lưu ý: MacOS Point-to-Point đôi khi cần set dst là chính nó hoặc gateway ảo
    runCmd(ipCmd.str());

    // ROUTING QUAN TRỌNG: Chia đôi Default Route để override (Fix Leak)
    // Thay vì thay đổi default gateway (rủi ro), ta add 2 route bao trùm toàn bộ IPv4
    runCmd("route add -net 0.0.0.0/1 -interface " + interfaceName);
    runCmd("route add -net 128.0.0.0/1 -interface " + interfaceName);

    // DNS Fix (Google DNS & Cloudflare)
    std::vector<std::string> services = {"Wi-Fi", "Ethernet", "Thunderbolt Bridge"};
    for (const auto& service : services) {
        runCmd("networksetup -setdnsservers \"" + service + "\" 8.8.8.8 1.1.1.1");
    }

    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask, const std::string& server) {
    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;
    return configureClientMode();
}

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load()) return -1;

    // macOS utun gửi kèm 4 byte header (Protocol Family)
    // Chúng ta cần đọc vào buffer tạm hoặc dịch chuyển con trỏ
    uint32_t packetHeader;
    struct iovec iov[2];

    // Header
    iov[0].iov_base = &packetHeader;
    iov[0].iov_len = sizeof(packetHeader);

    // Data
    iov[1].iov_base = buffer;
    iov[1].iov_len = maxSize;

    int n = readv(tunFd, iov, 2);

    if (n > 4) {
        bytesReceived += (n - 4);
        return (n - 4); // Trả về kích thước thực của IP packet (bỏ header)
    }
    return -1;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load()) return -1;

    // macOS utun yêu cầu 4 byte header trước gói tin IP
    // AF_INET = 2, phải ở dạng Network Byte Order (Big Endian)
    uint32_t family = htonl(AF_INET);

    struct iovec iov[2];
    iov[0].iov_base = &family;
    iov[0].iov_len = sizeof(family);

    iov[1].iov_base = (void*)buffer;
    iov[1].iov_len = size;

    int n = writev(tunFd, iov, 2);

    if (n > 4) {
        bytesSent += size;
        return size;
    }
    return -1;
}

void TUNInterface::close() {
    if (!isOpen.load()) return;

    std::cout << "[TUN] Restoring network configuration...\n";

    // 1. Remove Routes
    runCmd("route delete -net 0.0.0.0/1");
    runCmd("route delete -net 128.0.0.0/1");

    if (!serverIP.empty()) {
        runCmd("route delete " + serverIP);
    }

    // 2. Restore DNS & IPv6 for ALL interfaces
    // We must mirror the list from configureClientMode to ensure no interface is left broken.
    std::vector<std::string> services = {
        "Wi-Fi",
        "Thunderbolt Ethernet",
        "USB 10/100/1000 LAN",
        "Ethernet"
    };

    for (const auto& service : services) {
        // Clear DNS (Return to DHCP/ISP default)
        runCmd("networksetup -setdnsservers \"" + service + "\" Empty");

        // Restore IPv6 (Return to Automatic)
        runCmd("networksetup -setv6automatic \"" + service + "\"");
    }

    ::close(tunFd);
    tunFd = -1;
    isOpen.store(false);
}

// Các hàm phụ trợ khác giữ nguyên hoặc stub
bool TUNInterface::setIP(const std::string& ip, const std::string& mask) { return true; }
bool TUNInterface::setRoutes() { return true; }
std::string TUNInterface::getDefaultInterface() { return "en0"; }
bool TUNInterface::executeCommand(const std::string& cmd) { return runCmd(cmd); }
void TUNInterface::resetStats() { bytesReceived = 0; bytesSent = 0; }
void TUNInterface::setIPv6Status(bool enable) { /* Optional on Mac */ }
