#include "tun_interface.h"
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

    // Cấu hình IP + peer
    std::ostringstream cmd;
    if (!serverIP.empty()) {
        cmd << "ifconfig " << interfaceName << " " << vpnIP << " " << serverIP
            << " netmask 255.255.255.0 up";
    } else {
        cmd << "ifconfig " << interfaceName << " " << vpnIP
            << " " << vpnIP << " netmask 255.255.255.0 up";
    }
    if (!executeCommand(cmd.str())) return false;

    // *** THÊM ROUTE CHO CLIENT IP CỤ THỂ ***
    std::ostringstream clientRouteCmd;
    clientRouteCmd << "route add -host " << vpnIP << " -interface " << interfaceName;
    executeCommand(clientRouteCmd.str());

    // *** THÊM ROUTE CHO VPN SUBNET ***
    std::ostringstream subnetRouteCmd;
    subnetRouteCmd << "route add -net 10.8.0.0/24 -interface " << interfaceName;
    executeCommand(subnetRouteCmd.str());

    // Route giữ kết nối tới server qua interface mặc định
    if (!serverIP.empty()) {
        std::ostringstream serverRouteCmd;
        serverRouteCmd << "route add -host " << serverIP << " -interface " << getDefaultInterface();
        executeCommand(serverRouteCmd.str());
    }

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

std::string TUNInterface::getDefaultGateway() {
    // macOS: có thể đọc từ "route -n get default"
    // Ở đây tạm stub để tránh lỗi linker
    return "";
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

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load()) return -1;
    int n = ::read(tunFd, buffer, maxSize);
    if (n > 0) bytesReceived += n;
    return n;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load()) return -1;
    int n = ::write(tunFd, buffer, size);
    if (n > 0) bytesSent += n;
    return n;
}

void TUNInterface::close() {
    if (isOpen.load() && tunFd >= 0) {
        ::close(tunFd);
        tunFd = -1;
        isOpen.store(false);
    }
}

void TUNInterface::resetStats() {
    bytesReceived = 0;
    bytesSent = 0;
}
