#include "tun_interface.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <fstream>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define TAP_WIN_IOCTL_GET_MAC               CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_VERSION           CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_MTU               CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_INFO              CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_LOG_LINE          CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_CONFIG_TUN            CTL_CODE(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_COMPONENT_ID "tap0901"

#endif

TUNInterface::TUNInterface(const std::string& name)
    : interfaceName(name), isOpen(false), tunFd(-1),
    vpnIP(""), subnetMask(""), serverIP(""),
    bytesReceived(0), bytesSent(0) {
#ifdef _WIN32
    // KHỞI TẠO 2 BIẾN MỚI
    memset(&readOverlapped, 0, sizeof(readOverlapped));
    memset(&writeOverlapped, 0, sizeof(writeOverlapped));
#endif
}

#ifdef _WIN32

TUNInterface::~TUNInterface() {
    // cleanup nếu cần, hoặc để trống
}
std::string TUNInterface::findTAPAdapter() {
    HKEY adapterKey;
    LONG status;
    DWORD len;

    status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapterKey);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[TUN] Failed to open adapter registry key\n";
        return "";
    }

    for (DWORD i = 0; ; i++) {
        char subkeyName[256];
        len = sizeof(subkeyName);

        status = RegEnumKeyExA(adapterKey, i, subkeyName, &len, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        HKEY subkey;
        std::string subkeyPath = std::string(ADAPTER_KEY) + "\\" + subkeyName;

        status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkeyPath.c_str(), 0, KEY_READ, &subkey);
        if (status != ERROR_SUCCESS) continue;

        char componentId[256] = {0};
        DWORD dataType;
        len = sizeof(componentId);

        status = RegQueryValueExA(subkey, "ComponentId", NULL, &dataType,
                                  (LPBYTE)componentId, &len);

        if (status == ERROR_SUCCESS && strcmp(componentId, TAP_COMPONENT_ID) == 0) {
            char netCfgInstanceId[256] = {0};
            len = sizeof(netCfgInstanceId);

            status = RegQueryValueExA(subkey, "NetCfgInstanceId", NULL, &dataType,
                                      (LPBYTE)netCfgInstanceId, &len);

            if (status == ERROR_SUCCESS) {
                RegCloseKey(subkey);
                RegCloseKey(adapterKey);
                std::cout << "[TUN] Found TAP adapter: " << netCfgInstanceId << std::endl;
                return std::string(netCfgInstanceId);
            }
        }

        RegCloseKey(subkey);
    }

    RegCloseKey(adapterKey);
    std::cerr << "[TUN] No TAP adapter found\n";
    return "";
}

std::string TUNInterface::getAdapterName() {
    std::string guid = findTAPAdapter();
    if (guid.empty()) return "";

    std::string connectionKey = std::string(NETWORK_KEY) + "\\" + guid + "\\Connection";

    HKEY connKey;
    LONG status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, connectionKey.c_str(), 0, KEY_READ, &connKey);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[TUN] Failed to open connection registry key\n";
        return "";
    }

    char name[256] = {0};
    DWORD len = sizeof(name);
    DWORD dataType;

    status = RegQueryValueExA(connKey, "Name", NULL, &dataType, (LPBYTE)name, &len);
    RegCloseKey(connKey);

    if (status == ERROR_SUCCESS) {
        std::cout << "[TUN] Adapter name: " << name << std::endl;
        return std::string(name);
    }

    return "";
}

bool TUNInterface::create() {
    if (isOpen.load()) return true;

    std::string tapGuid = findTAPAdapter();
    if (tapGuid.empty()) {
        std::cerr << "[TUN] No TAP adapter found. Please install TAP-Windows.\n";
        return false;
    }

    interfaceName = getAdapterName();
    if (interfaceName.empty()) {
        interfaceName = "TAP-Windows Adapter";
    }

    std::string devicePath = "\\\\.\\Global\\" + tapGuid + ".tap";

    HANDLE handle = CreateFileA(
        devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        NULL
        );

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "[TUN] Failed to open TAP device: " << GetLastError() << std::endl;
        return false;
    }

    tunFd = (int)(intptr_t)handle;

    // TẠO EVENT MỘT LẦN DUY NHẤT Ở ĐÂY
    readOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    writeOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (readOverlapped.hEvent == NULL || writeOverlapped.hEvent == NULL) {
        std::cerr << "[TUN] Failed to create overlapped events\n";
        CloseHandle(handle);
        tunFd = -1;
        return false;
    }

    // Set media status to connected
    ULONG status = TRUE;
    DWORD len;
    if (!DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
        std::cerr << "[TUN] Failed to set media status\n";
        CloseHandle(handle);
        tunFd = -1;
        return false;
    }

    isOpen.store(true);
    std::cout << "[TUN] TAP device opened successfully\n";
    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask,
                             const std::string& server) {
    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;

    return configureClientMode();
}

std::string TUNInterface::getInterfaceIndex(const std::string& adapterName) {
    FILE* pipe = _popen(("netsh interface ipv4 show interfaces | findstr \"" + adapterName + "\"").c_str(), "r");
    if (!pipe) return "";

    char buffer[256];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);

    // Extract index (first number in line)
    std::istringstream iss(result);
    std::string idx;
    iss >> idx; // First token is the index

    std::cout << "[TUN] Interface '" << adapterName << "' has index: " << idx << "\n";
    return idx;
}

bool TUNInterface::configureClientMode() {
    if (!isOpen.load()) return false;

    // ✅ CRITICAL: Get old gateway BEFORE any configuration
    std::string oldGateway = getDefaultGateway();

    if (oldGateway.empty() || oldGateway == "0.0.0.0" || oldGateway == "10.8.0.1") {
        std::cout << "[TUN] Warning: Could not detect real gateway, trying common ones\n";
        std::vector<std::string> commonGateways = {"10.10.49.1", "192.168.1.1", "192.168.0.1", "10.0.0.1"};
        for (const auto& gw : commonGateways) {
            std::ostringstream testCmd;
            testCmd << "ping -n 1 -w 100 " << gw << " >nul 2>&1";
            if (executeCommand(testCmd.str())) {
                oldGateway = gw;
                std::cout << "[TUN] Found working gateway: " << oldGateway << "\n";
                break;
            }
        }
    }

    if (oldGateway.empty() || oldGateway == "0.0.0.0") {
        std::cerr << "[TUN] ✗ Cannot detect default gateway!\n";
        return false;
    }

    std::cout << "[TUN] Old gateway (saved): " << oldGateway << std::endl;

    HANDLE handle = (HANDLE)(intptr_t)tunFd;

    // ✅ Step 1: Configure TAP Point-to-Point
    ULONG ep[3];
    DWORD len;

    ep[0] = inet_addr(vpnIP.c_str());
    ep[1] = inet_addr("10.8.0.1");
    ep[2] = inet_addr(subnetMask.c_str());

    if (!DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
                         ep, sizeof(ep), ep, sizeof(ep), &len, NULL)) {
        std::cerr << "[TUN] Point-to-Point config failed: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "[TUN] ✓ Point-to-Point configured\n";
    Sleep(500);

    // ✅ Step 2: Set IP WITHOUT gateway first
    std::ostringstream ipCmd;
    ipCmd << "netsh interface ip set address name=\"" << interfaceName
          << "\" source=static addr=" << vpnIP
          << " mask=" << subnetMask;

    if (!executeCommand(ipCmd.str())) {
        std::cerr << "[TUN] ✗ Failed to set IP address\n";
        return false;
    }

    std::cout << "[TUN] ✓ IP address configured\n";
    Sleep(1000);

    // ✅ Step 3: Get interface index (metric sẽ dùng index thay vì tên)
    std::string interfaceIndex = getInterfaceIndex(interfaceName);
    if (interfaceIndex.empty()) {
        std::cerr << "[TUN] ✗ Cannot get interface index\n";
        interfaceIndex = "16"; // Fallback
    }
    std::cout << "[TUN] Interface index: " << interfaceIndex << "\n";

    // ✅ Step 4: CRITICAL FIX - Save old gateway
    if (!serverIP.empty() && !oldGateway.empty() && oldGateway != "0.0.0.0") {
        std::ostringstream saveCmd;
        saveCmd << "echo " << oldGateway << " > C:\\vpn_old_gateway.txt";
        executeCommand(saveCmd.str());

        // Protect server route FIRST (before changing default route)
        executeCommand("route delete " + serverIP + " >nul 2>&1");
        Sleep(200);

        std::ostringstream serverRouteCmd;
        serverRouteCmd << "route add " << serverIP << " mask 255.255.255.255 "
                       << oldGateway;
        if (executeCommand(serverRouteCmd.str())) {
            std::cout << "[TUN] ✓ Server route protected via " << oldGateway << "\n";
        }
    }

    Sleep(500);

    // ✅ Step 5: Delete old default routes
    executeCommand("route delete 0.0.0.0 >nul 2>&1");
    Sleep(200);

    // ✅ Step 6: Add VPN default route (CÚ PHÁP ĐÚNG)
    std::ostringstream defaultRouteCmd;
    defaultRouteCmd << "route add 0.0.0.0 mask 0.0.0.0 10.8.0.1 IF " << interfaceIndex;

    if (executeCommand(defaultRouteCmd.str())) {
        std::cout << "[TUN] ✓ Default route added via IF " << interfaceIndex << "\n";
    } else {
        std::cerr << "[TUN] ✗ Failed to add default route\n";
        // Don't return false - continue with split routes as backup
    }

    Sleep(500);

    // ✅ Step 7: Add VPN subnet route
    std::ostringstream vpnRouteCmd;
    vpnRouteCmd << "route delete 10.8.0.0 >nul 2>&1";
    executeCommand(vpnRouteCmd.str());
    Sleep(200);

    vpnRouteCmd.str("");
    vpnRouteCmd.clear();
    vpnRouteCmd << "route add 10.8.0.0 mask 255.255.255.0 10.8.0.1 IF " << interfaceIndex;
    executeCommand(vpnRouteCmd.str());

    Sleep(500);

    // ✅ Step 8: Add split routes as backup (covers all IPs)
    executeCommand("route delete 0.0.0.0 mask 128.0.0.0 >nul 2>&1");
    executeCommand("route delete 128.0.0.0 mask 128.0.0.0 >nul 2>&1");
    Sleep(200);

    std::ostringstream route1Cmd, route2Cmd;
    route1Cmd << "route add 0.0.0.0 mask 128.0.0.0 10.8.0.1 IF " << interfaceIndex;
    route2Cmd << "route add 128.0.0.0 mask 128.0.0.0 10.8.0.1 IF " << interfaceIndex;

    if (executeCommand(route1Cmd.str()) && executeCommand(route2Cmd.str())) {
        std::cout << "[TUN] ✓ Split routes added\n";
    }

    // ✅ Step 9: Set DNS
    std::ostringstream dns1Cmd, dns2Cmd;
    dns1Cmd << "netsh interface ip set dns name=\"" << interfaceName
            << "\" source=static addr=8.8.8.8 register=none validate=no";
    dns2Cmd << "netsh interface ip add dns name=\"" << interfaceName
            << "\" addr=8.8.4.4 index=2 validate=no";

    executeCommand(dns1Cmd.str());
    executeCommand(dns2Cmd.str());
    std::cout << "[TUN] ✓ DNS configured\n";

    // ✅ Step 10: Flush caches
    executeCommand("ipconfig /flushdns");
    executeCommand("arp -d *");

    // ✅ Step 11: Set interface metric (KHÔNG dùng netsh - dùng route)
    std::ostringstream metricCmd;
    metricCmd << "netsh interface ip set interface \"" << interfaceName
              << "\" metric=1";
    executeCommand(metricCmd.str());

    std::cout << "[TUN] ✓ Client mode fully configured\n";

    // ✅ Final verification
    std::cout << "\n[TUN] === VERIFICATION ===\n";
    system(("netsh interface ip show config name=\"" + interfaceName + "\"").c_str());
    std::cout << "\n[TUN] Current default routes:\n";
    system("route print 0.0.0.0");

    return true;
}

std::string TUNInterface::getDefaultGateway() {
    ULONG bufferSize = 15000;
    PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
    }

    std::string gateway;
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            // ✅ Skip TAP adapters and loopback
            std::string adapterName = adapter->Description;
            if (adapterName.find("TAP-Windows") != std::string::npos ||
                adapterName.find("TAP-Win32") != std::string::npos) {
                adapter = adapter->Next;
                continue;
            }

            // ✅ Look for active Ethernet or WiFi adapter
            if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
                adapter->Type == IF_TYPE_IEEE80211) {

                std::string gw = adapter->GatewayList.IpAddress.String;

                // ✅ Filter out VPN gateways and invalid gateways
                if (gw != "0.0.0.0" && !gw.empty() &&
                    gw.find("10.8.0") == std::string::npos) {  // Skip VPN subnet
                    gateway = gw;
                    std::cout << "[TUN] Found gateway " << gateway
                              << " on " << adapter->Description << "\n";
                    break;
                }
            }
            adapter = adapter->Next;
        }
    }

    free(adapterInfo);
    return gateway;
}

std::string TUNInterface::getDefaultInterface() {
    return interfaceName;
}

// tun_interface_win.cpp

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load() || tunFd < 0) return -1;

    HANDLE handle = (HANDLE)(intptr_t)tunFd;
    // BỎ: OVERLAPPED overlapped = {0};
    // BỎ: overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    ResetEvent(readOverlapped.hEvent); // DÙNG LẠI EVENT

    DWORD bytesRead = 0;
    BOOL result = ReadFile(handle, buffer, maxSize, &bytesRead, &readOverlapped); // DÙNG readOverlapped

    if (!result) {
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD timeout = 0;
            DWORD waitResult = WaitForSingleObject(readOverlapped.hEvent, timeout);

            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(handle, &readOverlapped, &bytesRead, FALSE); // DÙNG readOverlapped
            } else {
                CancelIo(handle);
                // BỎ: CloseHandle(overlapped.hEvent);
                return 0;
            }
        } else {
            // BỎ: CloseHandle(overlapped.hEvent);
            return -1;
        }
    }

    // BỎ: CloseHandle(overlapped.hEvent);

    if (bytesRead > 0) {
        bytesReceived += bytesRead;
    }

    return bytesRead;
}

// tun_interface_win.cpp

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load() || tunFd < 0 || size <= 0) return -1;

    HANDLE handle = (HANDLE)(intptr_t)tunFd;
    // BỎ: OVERLAPPED overlapped = {0};
    // BỎ: overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    ResetEvent(writeOverlapped.hEvent); // DÙNG LẠI EVENT

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(handle, buffer, size, &bytesWritten, &writeOverlapped); // DÙNG writeOverlapped

    if (!result) {
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD timeout = 0;
            DWORD waitResult = WaitForSingleObject(writeOverlapped.hEvent, timeout);

            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(handle, &writeOverlapped, &bytesWritten, FALSE); // DÙNG writeOverlapped
            } else {
                CancelIo(handle);
                // BỎ: CloseHandle(overlapped.hEvent);
                return 0;
            }
        } else {
            // BỎ: CloseHandle(overlapped.hEvent);
            return -1;
        }
    }

    // BỎ: CloseHandle(overlapped.hEvent);

    if (bytesWritten > 0) {
        bytesSent += bytesWritten;
    }

    return bytesWritten;
}

void TUNInterface::close() {
    if (!isOpen.load() || tunFd < 0) return;

    std::cout << "[TUN] Cleaning up interface..." << std::endl;

    // Restore old gateway
    std::ifstream gwFile("C:\\vpn_old_gateway.txt");
    std::string oldGateway;
    if (gwFile.is_open()) {
        std::getline(gwFile, oldGateway);
        gwFile.close();

        if (!oldGateway.empty()) {
            executeCommand("route delete 0.0.0.0");

            std::ostringstream restoreCmd;
            restoreCmd << "route add 0.0.0.0 mask 0.0.0.0 " << oldGateway << " metric 1";
            if (executeCommand(restoreCmd.str())) {
                std::cout << "[TUN] âœ“ Default route restored\n";
            }
        }

        DeleteFileA("C:\\vpn_old_gateway.txt");
    }

    // Delete VPN routes
    if (!serverIP.empty()) {
        std::ostringstream delCmd;
        delCmd << "route delete " << serverIP;
        executeCommand(delCmd.str());
    }

    executeCommand("route delete 10.8.0.0");

    HANDLE handle = (HANDLE)(intptr_t)tunFd;
    // GIẢI PHÓNG EVENTS
    if (readOverlapped.hEvent) CloseHandle(readOverlapped.hEvent);
    if (writeOverlapped.hEvent) CloseHandle(writeOverlapped.hEvent);

    CloseHandle(handle);

    tunFd = -1;
    isOpen.store(false);

    std::cout << "[TUN] âœ“ Cleanup complete\n";
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    int ret = system(cmd.c_str());
    return (ret == 0);
}

bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
    vpnIP = ip;
    subnetMask = mask;

    std::ostringstream cmd;
    cmd << "netsh interface ip set address name=\"" << interfaceName
        << "\" static " << vpnIP << " " << subnetMask;
    return executeCommand(cmd.str());
}

bool TUNInterface::setRoutes() {
    if (serverIP.empty()) return true;

    std::ostringstream cmd;
    cmd << "route add 0.0.0.0 mask 0.0.0.0 " << vpnIP << " metric 1";
    return executeCommand(cmd.str());
}

void TUNInterface::resetStats() {
    bytesReceived = 0;
    bytesSent = 0;
}

#endif // _WIN32
