#include "tun_interface.h"
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <thread>
#include <chrono>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// TAP-Windows adapter IOCTL codes
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
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

TUNInterface::TUNInterface(const std::string& name)
    : interfaceName(name), isOpen(false), tunFd(-1),
    vpnIP(""), subnetMask(""), serverIP(""),
    bytesReceived(0), bytesSent(0) {}

TUNInterface::~TUNInterface() {
    close();
}

std::string TUNInterface::findTAPAdapter() {
    HKEY adapterKey;
    LONG status;
    DWORD index = 0;
    std::string tapGuid;

    status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapterKey);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ERROR] Cannot open adapter registry key. Error code: " << status << std::endl;
        std::cerr << "[INFO] Please run as Administrator" << std::endl;
        return "";
    }

    std::cout << "[INFO] Searching for TAP adapter..." << std::endl;

    while (true) {
        char subkeyName[256];
        DWORD subkeyNameLen = sizeof(subkeyName);

        status = RegEnumKeyExA(adapterKey, index++, subkeyName, &subkeyNameLen,
                               NULL, NULL, NULL, NULL);

        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        HKEY subkey;
        std::string subkeyPath = std::string(ADAPTER_KEY) + "\\" + subkeyName;

        status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkeyPath.c_str(), 0, KEY_READ, &subkey);
        if (status != ERROR_SUCCESS) continue;

        char componentId[256] = {0};
        DWORD componentIdLen = sizeof(componentId);
        DWORD dataType;

        status = RegQueryValueExA(subkey, "ComponentId", NULL, &dataType,
                                  (LPBYTE)componentId, &componentIdLen);

        if (status == ERROR_SUCCESS && dataType == REG_SZ) {
            std::cout << "[DEBUG] Found adapter: " << componentId << std::endl;

            // Tìm các loại TAP adapter phổ biến
            if (strstr(componentId, "tap0901") != NULL ||
                strstr(componentId, "tap0801") != NULL ||
                strstr(componentId, "wintun") != NULL) {

                char netCfgInstanceId[256] = {0};
                DWORD netCfgInstanceIdLen = sizeof(netCfgInstanceId);

                status = RegQueryValueExA(subkey, "NetCfgInstanceId", NULL, &dataType,
                                          (LPBYTE)netCfgInstanceId, &netCfgInstanceIdLen);

                if (status == ERROR_SUCCESS && dataType == REG_SZ) {
                    tapGuid = netCfgInstanceId;
                    std::cout << "[INFO] Found TAP adapter GUID: " << tapGuid << std::endl;
                    RegCloseKey(subkey);
                    break;
                }
            }
        }

        RegCloseKey(subkey);
    }

    RegCloseKey(adapterKey);

    if (tapGuid.empty()) {
        std::cerr << "\n[ERROR] TAP adapter not found!" << std::endl;
        std::cerr << "[SOLUTION] Please install TAP-Windows adapter:" << std::endl;
        std::cerr << "  1. Download OpenVPN: https://openvpn.net/community-downloads/" << std::endl;
        std::cerr << "  2. Install it (TAP driver will be included)" << std::endl;
        std::cerr << "  3. Or download TAP-Windows separately from OpenVPN GitHub" << std::endl;
    }

    return tapGuid;
}

bool TUNInterface::create() {
    if (isOpen.load()) {
        std::cout << "[INFO] TAP adapter already opened" << std::endl;
        return true;
    }

    std::cout << "\n[INFO] ========== Creating TUN Interface ==========" << std::endl;

    std::string tapGuid = findTAPAdapter();
    if (tapGuid.empty()) {
        return false;
    }

    std::string devicePath = "\\\\.\\Global\\" + tapGuid + ".tap";
    std::cout << "[INFO] Opening TAP device: " << devicePath << std::endl;

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
        DWORD err = GetLastError();
        std::cerr << "[ERROR] Cannot open TAP device!" << std::endl;
        std::cerr << "[ERROR] Error code: " << err << std::endl;

        switch(err) {
        case ERROR_FILE_NOT_FOUND:
            std::cerr << "[INFO] TAP device file not found. Please install TAP-Windows driver." << std::endl;
            break;
        case ERROR_ACCESS_DENIED:
            std::cerr << "[INFO] Access denied. Please run as Administrator!" << std::endl;
            break;
        case ERROR_SHARING_VIOLATION:
            std::cerr << "[INFO] Device is being used by another application." << std::endl;
            break;
        default:
            std::cerr << "[INFO] Unknown error. Try running as Administrator." << std::endl;
        }
        return false;
    }

    tunFd = (int)(intptr_t)handle;
    interfaceName = tapGuid;

    // Set media status to connected
    ULONG status = 1;
    DWORD len;
    if (!DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
        DWORD err = GetLastError();
        std::cerr << "[WARN] Failed to set media status. Error code: " << err << std::endl;
    } else {
        std::cout << "[INFO] Media status set to connected" << std::endl;
    }

    isOpen.store(true);
    std::cout << "[SUCCESS] TAP adapter opened successfully!" << std::endl;
    std::cout << "[INFO] ============================================\n" << std::endl;
    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask,
                             const std::string& server) {
    std::cout << "\n[INFO] ========== Configuring TUN Interface ==========" << std::endl;
    std::cout << "[INFO] VPN IP: " << ip << std::endl;
    std::cout << "[INFO] Subnet Mask: " << mask << std::endl;
    std::cout << "[INFO] Gateway: 10.8.0.1" << std::endl;

    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;

    bool result = configureClientMode();

    if (result) {
        std::cout << "[SUCCESS] TUN interface configured successfully!" << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to configure TUN interface!" << std::endl;
    }
    std::cout << "[INFO] ================================================\n" << std::endl;

    return result;
}

std::string TUNInterface::getAdapterFriendlyName() {
    std::string connectionKey = std::string(NETWORK_CONNECTIONS_KEY) + "\\" + interfaceName + "\\Connection";

    HKEY key;
    LONG status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, connectionKey.c_str(), 0, KEY_READ, &key);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[WARN] Cannot read adapter friendly name from registry" << std::endl;
        return "TAP-Windows Adapter V9";  // Fallback name
    }

    char name[256] = {0};
    DWORD nameLen = sizeof(name);
    DWORD dataType;

    status = RegQueryValueExA(key, "Name", NULL, &dataType, (LPBYTE)name, &nameLen);
    RegCloseKey(key);

    if (status == ERROR_SUCCESS && dataType == REG_SZ) {
        std::cout << "[INFO] Adapter friendly name: " << name << std::endl;
        return std::string(name);
    }

    return "TAP-Windows Adapter V9";
}

std::string TUNInterface::getInterfaceIndex() {
    // Get interface index for the TAP adapter
    ULONG bufferSize = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
    }

    std::string interfaceIndex;
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            // Look for our TAP adapter by checking the adapter name or description
            std::string adapterDesc = pAdapter->Description;
            if (adapterDesc.find("TAP") != std::string::npos) {
                interfaceIndex = std::to_string(pAdapter->Index);
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }

    free(pAdapterInfo);
    return interfaceIndex.empty() ? "1" : interfaceIndex;
}

bool TUNInterface::configureClientMode() {
    if (!isOpen.load()) {
        std::cerr << "[ERROR] TUN interface is not open" << std::endl;
        return false;
    }

    HANDLE handle = (HANDLE)(intptr_t)tunFd;

    std::cout << "[INFO] Configuring TUN mode..." << std::endl;
    std::cout << "[INFO] Local IP: " << vpnIP << std::endl;
    std::cout << "[INFO] Remote IP (Gateway): 10.8.0.1" << std::endl;
    std::cout << "[INFO] Netmask: " << subnetMask << std::endl;

    // CRITICAL: Use CONFIG_POINT_TO_POINT first for better compatibility
    ULONG ep_p2p[2];
    ep_p2p[0] = inet_addr(vpnIP.c_str());        // Local VPN IP (e.g., 10.8.0.2)
    ep_p2p[1] = inet_addr("10.8.0.1");           // Remote endpoint (gateway)

    DWORD len;

    // Try point-to-point configuration first (more reliable on Windows)
    if (!DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
                         ep_p2p, sizeof(ep_p2p), ep_p2p, sizeof(ep_p2p), &len, NULL)) {
        DWORD err = GetLastError();
        std::cerr << "[ERROR] CONFIG_POINT_TO_POINT failed! Error: " << err << std::endl;

        // Try TUN mode as fallback
        std::cout << "[INFO] Trying TUN mode configuration..." << std::endl;
        ULONG ep[3];
        ep[0] = inet_addr(vpnIP.c_str());
        ep[1] = inet_addr("10.8.0.1");
        ep[2] = inet_addr(subnetMask.c_str());

        if (!DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_TUN,
                             ep, sizeof(ep), ep, sizeof(ep), &len, NULL)) {
            DWORD err2 = GetLastError();
            std::cerr << "[ERROR] Both CONFIG methods failed! TUN error: " << err2 << std::endl;
            return false;
        }
        std::cout << "[INFO] TAP configured using TUN mode" << std::endl;
    } else {
        std::cout << "[SUCCESS] TAP configured using point-to-point mode" << std::endl;
    }

    // Wait for device to be ready
    std::cout << "[INFO] Waiting for adapter to initialize..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Get adapter name
    std::string adapterName = getAdapterFriendlyName();
    if (adapterName.empty()) {
        std::cerr << "[ERROR] Cannot get adapter name" << std::endl;
        return false;
    }

    std::cout << "[INFO] Configuring IP address on adapter: " << adapterName << std::endl;

    // CRITICAL: Set IP address explicitly using netsh
    std::ostringstream ipCmd;
    ipCmd << "netsh interface ip set address name=\"" << adapterName
          << "\" source=static addr=" << vpnIP << " mask=" << subnetMask
          << " gateway=10.8.0.1";

    if (!executeCommand(ipCmd.str())) {
        std::cerr << "[WARN] Failed to set IP via netsh, trying alternative method..." << std::endl;

        // Alternative: Set IP without gateway first
        std::ostringstream ipCmd2;
        ipCmd2 << "netsh interface ip set address name=\"" << adapterName
               << "\" source=static addr=" << vpnIP << " mask=" << subnetMask;
        executeCommand(ipCmd2.str());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    // Verify IP is set correctly
    std::cout << "[INFO] Verifying IP configuration..." << std::endl;
    std::ostringstream verifyCmd;
    verifyCmd << "netsh interface ip show address \"" << adapterName << "\"";
    executeCommand(verifyCmd.str());

    // Enable the interface explicitly
    std::cout << "[INFO] Enabling network adapter..." << std::endl;
    std::ostringstream enableCmd;
    enableCmd << "netsh interface set interface \"" << adapterName << "\" enable";
    executeCommand(enableCmd.str());

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Configure routing
    std::cout << "[INFO] Configuring routes..." << std::endl;

    // Add route for VPN subnet via VPN gateway
    std::ostringstream routeCmd;
    routeCmd << "route delete 10.8.0.0 >nul 2>&1 & route add 10.8.0.0 mask 255.255.255.0 10.8.0.1 metric 1 if " << getInterfaceIndex();
    executeCommand(routeCmd.str());

    // Save and configure default gateway
    std::string oldGateway = getDefaultGateway();
    if (!oldGateway.empty()) {
        std::cout << "[INFO] Current default gateway: " << oldGateway << std::endl;

        // Save old gateway
        std::ofstream gwFile("C:\\vpn_old_gateway.txt");
        if (gwFile.is_open()) {
            gwFile << oldGateway;
            gwFile.close();
            std::cout << "[INFO] Old gateway saved" << std::endl;
        }

        // Add route for VPN server via old gateway (if server IP is provided)
        if (!serverIP.empty()) {
            std::cout << "[INFO] Adding route for VPN server..." << std::endl;
            std::ostringstream serverRouteCmd;
            serverRouteCmd << "route delete " << serverIP << " >nul 2>&1 & route add "
                           << serverIP << " mask 255.255.255.255 " << oldGateway << " metric 1";
            executeCommand(serverRouteCmd.str());
        }
    }

    // Set default route via VPN (optional - comment out if you want split-tunnel)
    std::cout << "[INFO] Setting default route via VPN..." << std::endl;
    std::ostringstream defaultRouteCmd;
    defaultRouteCmd << "route add 0.0.0.0 mask 0.0.0.0 10.8.0.1 metric 1";
    executeCommand(defaultRouteCmd.str());

    // Set DNS servers
    std::cout << "[INFO] Setting DNS servers..." << std::endl;
    std::ostringstream dnsCmd;
    dnsCmd << "netsh interface ip set dns name=\"" << adapterName << "\" source=static addr=8.8.8.8";
    executeCommand(dnsCmd.str());

    // Add secondary DNS
    std::ostringstream dns2Cmd;
    dns2Cmd << "netsh interface ip add dns name=\"" << adapterName << "\" addr=8.8.4.4 index=2";
    executeCommand(dns2Cmd.str());

    // Flush DNS cache
    executeCommand("ipconfig /flushdns");

    std::cout << "[SUCCESS] Client mode configured successfully!" << std::endl;
    std::cout << "[INFO] VPN IP: " << vpnIP << " should now be active" << std::endl;

    return true;
}

std::string TUNInterface::getDefaultGateway() {
    ULONG bufferSize = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
    }

    std::string gateway;
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->GatewayList.IpAddress.String[0] != '0') {
                gateway = pAdapter->GatewayList.IpAddress.String;
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }

    free(pAdapterInfo);
    return gateway;
}

std::string TUNInterface::getDefaultInterface() {
    return interfaceName;
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    std::cout << "[CMD] " << cmd << std::endl;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "[WARN] Command returned non-zero: " << ret << std::endl;
    }
    return (ret == 0);
}

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load() || tunFd < 0) return -1;

    HANDLE handle = (HANDLE)(intptr_t)tunFd;
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    DWORD bytesRead = 0;
    BOOL result = ReadFile(handle, buffer, maxSize, &bytesRead, &overlapped);

    if (!result) {
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 100);
            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(handle, &overlapped, &bytesRead, FALSE);
            } else {
                CancelIo(handle);
                CloseHandle(overlapped.hEvent);
                return 0;
            }
        } else {
            CloseHandle(overlapped.hEvent);
            return -1;
        }
    }

    CloseHandle(overlapped.hEvent);

    if (bytesRead > 0) {
        bytesReceived += bytesRead;
        return bytesRead;
    }

    return 0;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load() || tunFd < 0) {
        std::cerr << "[TUN WRITE] Interface not open" << std::endl;
        return -1;
    }
    if (size <= 0) {
        std::cerr << "[TUN WRITE] Invalid size: " << size << std::endl;
        return 0;
    }

    std::cout << "[TUN WRITE] Attempting to write " << size << " bytes" << std::endl;

    HANDLE handle = (HANDLE)(intptr_t)tunFd;
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(handle, buffer, size, &bytesWritten, &overlapped);

    if (!result) {
        if (GetLastError() == ERROR_IO_PENDING) {
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 1000);
            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(handle, &overlapped, &bytesWritten, FALSE);
            } else {
                CancelIo(handle);
                CloseHandle(overlapped.hEvent);
                return 0;
            }
        } else {
            CloseHandle(overlapped.hEvent);
            return -1;
        }
    }

    CloseHandle(overlapped.hEvent);

    if (bytesWritten > 0) {
        bytesSent += bytesWritten;
        std::cout << "[TUN WRITE] Successfully wrote " << bytesWritten << " bytes" << std::endl;
        return bytesWritten;
    }

    std::cerr << "[TUN WRITE] Wrote 0 bytes" << std::endl;
    return 0;
}

bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
    vpnIP = ip;
    subnetMask = mask;

    std::string adapterName = getAdapterFriendlyName();
    std::ostringstream cmd;
    cmd << "netsh interface ip set address \"" << adapterName
        << "\" static " << vpnIP << " " << subnetMask;

    return executeCommand(cmd.str());
}

bool TUNInterface::setRoutes() {
    if (serverIP.empty()) return true;

    std::ostringstream cmd;
    cmd << "route add 0.0.0.0 mask 0.0.0.0 " << vpnIP;
    return executeCommand(cmd.str());
}

void TUNInterface::close() {
    if (isOpen.load() && tunFd >= 0) {
        std::cout << "\n[INFO] ========== Closing TUN Interface ==========" << std::endl;

        // Restore old gateway
        std::ifstream gwFile("C:\\vpn_old_gateway.txt");
        if (gwFile.is_open()) {
            std::string oldGateway;
            std::getline(gwFile, oldGateway);
            gwFile.close();

            if (!oldGateway.empty()) {
                std::cout << "[INFO] Restoring network configuration..." << std::endl;

                // Delete VPN routes
                executeCommand("route delete 0.0.0.0");
                executeCommand("route delete 10.8.0.0");

                // Restore default gateway
                std::ostringstream restoreCmd;
                restoreCmd << "route add 0.0.0.0 mask 0.0.0.0 " << oldGateway;
                executeCommand(restoreCmd.str());

                std::cout << "[INFO] Network configuration restored" << std::endl;
            }

            DeleteFileA("C:\\vpn_old_gateway.txt");
        }

        HANDLE handle = (HANDLE)(intptr_t)tunFd;
        CloseHandle(handle);
        tunFd = -1;
        isOpen.store(false);

        std::cout << "[SUCCESS] TAP adapter closed successfully" << std::endl;
        std::cout << "[INFO] ===========================================\n" << std::endl;
    }
}

void TUNInterface::resetStats() {
    bytesReceived = 0;
    bytesSent = 0;
}


// #include "tun_interface.h"
// #include <winsock2.h>
// #include <windows.h>
// #include <winioctl.h>
// #include <iphlpapi.h>
// #include <iostream>
// #include <sstream>
// #include <fstream>
// #include <thread>
// #include <chrono>

// #pragma comment(lib, "iphlpapi.lib")
// #pragma comment(lib, "ws2_32.lib")

// // TAP-Windows adapter IOCTL codes
// #define TAP_WIN_IOCTL_GET_MAC               CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_GET_VERSION           CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_GET_MTU               CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_GET_INFO              CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_SET_MEDIA_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_GET_LOG_LINE          CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define TAP_WIN_IOCTL_CONFIG_TUN            CTL_CODE(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

// #define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
// #define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

// TUNInterface::TUNInterface(const std::string& name)
//     : interfaceName(name), isOpen(false), tunFd(-1),
//     vpnIP(""), subnetMask(""), serverIP(""),
//     bytesReceived(0), bytesSent(0) {}

// TUNInterface::~TUNInterface() {
//     close();
// }

// std::string TUNInterface::findTAPAdapter() {
//     HKEY adapterKey;
//     LONG status;
//     DWORD index = 0;
//     std::string tapGuid;

//     status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapterKey);
//     if (status != ERROR_SUCCESS) {
//         std::cerr << "[ERROR] Cannot open adapter registry key. Error code: " << status << std::endl;
//         std::cerr << "[INFO] Please run as Administrator" << std::endl;
//         return "";
//     }

//     std::cout << "[INFO] Searching for TAP adapter..." << std::endl;

//     while (true) {
//         char subkeyName[256];
//         DWORD subkeyNameLen = sizeof(subkeyName);

//         status = RegEnumKeyExA(adapterKey, index++, subkeyName, &subkeyNameLen,
//                                NULL, NULL, NULL, NULL);

//         if (status == ERROR_NO_MORE_ITEMS) break;
//         if (status != ERROR_SUCCESS) continue;

//         HKEY subkey;
//         std::string subkeyPath = std::string(ADAPTER_KEY) + "\\" + subkeyName;

//         status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkeyPath.c_str(), 0, KEY_READ, &subkey);
//         if (status != ERROR_SUCCESS) continue;

//         char componentId[256] = {0};
//         DWORD componentIdLen = sizeof(componentId);
//         DWORD dataType;

//         status = RegQueryValueExA(subkey, "ComponentId", NULL, &dataType,
//                                   (LPBYTE)componentId, &componentIdLen);

//         if (status == ERROR_SUCCESS && dataType == REG_SZ) {
//             std::cout << "[DEBUG] Found adapter: " << componentId << std::endl;

//             // Tìm các loại TAP adapter phổ biến
//             if (strstr(componentId, "tap0901") != NULL ||
//                 strstr(componentId, "tap0801") != NULL ||
//                 strstr(componentId, "wintun") != NULL) {

//                 char netCfgInstanceId[256] = {0};
//                 DWORD netCfgInstanceIdLen = sizeof(netCfgInstanceId);

//                 status = RegQueryValueExA(subkey, "NetCfgInstanceId", NULL, &dataType,
//                                           (LPBYTE)netCfgInstanceId, &netCfgInstanceIdLen);

//                 if (status == ERROR_SUCCESS && dataType == REG_SZ) {
//                     tapGuid = netCfgInstanceId;
//                     std::cout << "[INFO] Found TAP adapter GUID: " << tapGuid << std::endl;
//                     RegCloseKey(subkey);
//                     break;
//                 }
//             }
//         }

//         RegCloseKey(subkey);
//     }

//     RegCloseKey(adapterKey);

//     if (tapGuid.empty()) {
//         std::cerr << "\n[ERROR] TAP adapter not found!" << std::endl;
//         std::cerr << "[SOLUTION] Please install TAP-Windows adapter:" << std::endl;
//         std::cerr << "  1. Download OpenVPN: https://openvpn.net/community-downloads/" << std::endl;
//         std::cerr << "  2. Install it (TAP driver will be included)" << std::endl;
//         std::cerr << "  3. Or download TAP-Windows separately from OpenVPN GitHub" << std::endl;
//     }

//     return tapGuid;
// }

// bool TUNInterface::create() {
//     if (isOpen.load()) {
//         std::cout << "[INFO] TAP adapter already opened" << std::endl;
//         return true;
//     }

//     std::cout << "\n[INFO] ========== Creating TUN Interface ==========" << std::endl;

//     std::string tapGuid = findTAPAdapter();
//     if (tapGuid.empty()) {
//         return false;
//     }

//     std::string devicePath = "\\\\.\\Global\\" + tapGuid + ".tap";
//     std::cout << "[INFO] Opening TAP device: " << devicePath << std::endl;

//     HANDLE handle = CreateFileA(
//         devicePath.c_str(),
//         GENERIC_READ | GENERIC_WRITE,
//         0,
//         NULL,
//         OPEN_EXISTING,
//         FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
//         NULL
//         );

//     if (handle == INVALID_HANDLE_VALUE) {
//         DWORD err = GetLastError();
//         std::cerr << "[ERROR] Cannot open TAP device!" << std::endl;
//         std::cerr << "[ERROR] Error code: " << err << std::endl;

//         switch(err) {
//         case ERROR_FILE_NOT_FOUND:
//             std::cerr << "[INFO] TAP device file not found. Please install TAP-Windows driver." << std::endl;
//             break;
//         case ERROR_ACCESS_DENIED:
//             std::cerr << "[INFO] Access denied. Please run as Administrator!" << std::endl;
//             break;
//         case ERROR_SHARING_VIOLATION:
//             std::cerr << "[INFO] Device is being used by another application." << std::endl;
//             break;
//         default:
//             std::cerr << "[INFO] Unknown error. Try running as Administrator." << std::endl;
//         }
//         return false;
//     }

//     tunFd = (int)(intptr_t)handle;
//     interfaceName = tapGuid;

//     // Set media status to connected
//     ULONG status = 1;
//     DWORD len;
//     if (!DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
//                          &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
//         DWORD err = GetLastError();
//         std::cerr << "[WARN] Failed to set media status. Error code: " << err << std::endl;
//     } else {
//         std::cout << "[INFO] Media status set to connected" << std::endl;
//     }

//     isOpen.store(true);
//     std::cout << "[SUCCESS] TAP adapter opened successfully!" << std::endl;
//     std::cout << "[INFO] ============================================\n" << std::endl;
//     return true;
// }

// bool TUNInterface::configure(const std::string& ip, const std::string& mask,
//                              const std::string& server) {
//     std::cout << "\n[INFO] ========== Configuring TUN Interface ==========" << std::endl;
//     std::cout << "[INFO] VPN IP: " << ip << std::endl;
//     std::cout << "[INFO] Subnet Mask: " << mask << std::endl;
//     std::cout << "[INFO] Gateway: 10.8.0.1" << std::endl;

//     vpnIP = ip;
//     subnetMask = mask;
//     serverIP = server;

//     bool result = configureClientMode();

//     if (result) {
//         std::cout << "[SUCCESS] TUN interface configured successfully!" << std::endl;
//     } else {
//         std::cerr << "[ERROR] Failed to configure TUN interface!" << std::endl;
//     }
//     std::cout << "[INFO] ================================================\n" << std::endl;

//     return result;
// }

// std::string TUNInterface::getAdapterFriendlyName() {
//     std::string connectionKey = std::string(NETWORK_CONNECTIONS_KEY) + "\\" + interfaceName + "\\Connection";

//     HKEY key;
//     LONG status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, connectionKey.c_str(), 0, KEY_READ, &key);
//     if (status != ERROR_SUCCESS) {
//         std::cerr << "[WARN] Cannot read adapter friendly name from registry" << std::endl;
//         return "TAP-Windows Adapter V9";  // Fallback name
//     }

//     char name[256] = {0};
//     DWORD nameLen = sizeof(name);
//     DWORD dataType;

//     status = RegQueryValueExA(key, "Name", NULL, &dataType, (LPBYTE)name, &nameLen);
//     RegCloseKey(key);

//     if (status == ERROR_SUCCESS && dataType == REG_SZ) {
//         std::cout << "[INFO] Adapter friendly name: " << name << std::endl;
//         return std::string(name);
//     }

//     return "TAP-Windows Adapter V9";
// }

// bool TUNInterface::configureClientMode() {
//     if (!isOpen.load()) {
//         std::cerr << "[ERROR] TUN interface is not open" << std::endl;
//         return false;
//     }

//     HANDLE handle = (HANDLE)(intptr_t)tunFd;

//     // Configure TUN mode with point-to-point
//     std::cout << "[INFO] Configuring TUN mode..." << std::endl;

//     ULONG ep[3];
//     ep[0] = inet_addr(vpnIP.c_str());           // Local VPN IP
//     ep[1] = inet_addr("10.8.0.1");              // Remote endpoint (gateway)
//     ep[2] = inet_addr(subnetMask.c_str());      // Netmask

//     DWORD len;
//     if (!DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_TUN,
//                          ep, sizeof(ep), ep, sizeof(ep), &len, NULL)) {
//         DWORD err = GetLastError();
//         std::cerr << "[ERROR] Failed to configure TUN mode!" << std::endl;
//         std::cerr << "[ERROR] Error code: " << err << std::endl;
//         std::cerr << "[INFO] This might be because:" << std::endl;
//         std::cerr << "  - TAP driver doesn't support TUN mode (too old)" << std::endl;
//         std::cerr << "  - Need to run as Administrator" << std::endl;
//         std::cerr << "  - Try using TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT instead" << std::endl;

//         // Try alternative method: CONFIG_POINT_TO_POINT
//         std::cout << "[INFO] Trying alternative configuration method..." << std::endl;
//         ULONG ep_p2p[2];
//         ep_p2p[0] = ep[0];  // local IP
//         ep_p2p[1] = ep[1];  // remote IP

//         if (!DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
//                              ep_p2p, sizeof(ep_p2p), ep_p2p, sizeof(ep_p2p), &len, NULL)) {
//             DWORD err2 = GetLastError();
//             std::cerr << "[ERROR] Alternative method also failed. Error code: " << err2 << std::endl;
//             return false;
//         }
//         std::cout << "[INFO] TAP configured using point-to-point mode" << std::endl;
//     } else {
//         std::cout << "[INFO] TAP configured in TUN mode successfully" << std::endl;
//     }

//     // Wait for adapter to be ready
//     std::cout << "[INFO] Waiting for adapter to be ready..." << std::endl;
//     std::this_thread::sleep_for(std::chrono::milliseconds(500));

//     // Get adapter name for netsh commands
//     std::string adapterName = getAdapterFriendlyName();
//     if (adapterName.empty()) {
//         std::cerr << "[ERROR] Cannot get adapter name" << std::endl;
//         return false;
//     }

//     // Configure IP address using netsh
//     std::cout << "[INFO] Setting IP address via netsh..." << std::endl;
//     std::ostringstream cmd;
//     cmd << "netsh interface ip set address \"" << adapterName
//         << "\" static " << vpnIP << " " << subnetMask;

//     if (!executeCommand(cmd.str())) {
//         std::cerr << "[ERROR] Failed to set IP address" << std::endl;
//         std::cerr << "[INFO] Try manually: netsh interface ip set address \""
//                   << adapterName << "\" static " << vpnIP << " " << subnetMask << std::endl;
//         // Don't return false here, continue with other configurations
//     }

//     std::this_thread::sleep_for(std::chrono::milliseconds(1000));

//     // Add route for VPN subnet
//     std::cout << "[INFO] Adding VPN subnet route..." << std::endl;
//     std::ostringstream routeCmd;
//     routeCmd << "route add 10.8.0.0 mask 255.255.255.0 10.8.0.1 metric 1";
//     executeCommand(routeCmd.str());

//     // Save and modify default gateway
//     std::string oldGateway = getDefaultGateway();
//     if (!oldGateway.empty()) {
//         std::cout << "[INFO] Current default gateway: " << oldGateway << std::endl;

//         // Save old gateway
//         std::ofstream gwFile("C:\\vpn_old_gateway.txt");
//         if (gwFile.is_open()) {
//             gwFile << oldGateway;
//             gwFile.close();
//             std::cout << "[INFO] Old gateway saved to C:\\vpn_old_gateway.txt" << std::endl;
//         }

//         // Add route for VPN server via old gateway
//         if (!serverIP.empty()) {
//             std::cout << "[INFO] Adding route for VPN server..." << std::endl;
//             std::ostringstream serverRouteCmd;
//             serverRouteCmd << "route add " << serverIP << " mask 255.255.255.255 "
//                            << oldGateway << " metric 1";
//             executeCommand(serverRouteCmd.str());
//         }
//     }

//     // Set default route via VPN
//     std::cout << "[INFO] Setting default route via VPN..." << std::endl;
//     std::ostringstream defaultRouteCmd;
//     defaultRouteCmd << "route add 0.0.0.0 mask 0.0.0.0 10.8.0.1 metric 1";
//     executeCommand(defaultRouteCmd.str());

//     // Set DNS servers
//     std::cout << "[INFO] Setting DNS servers..." << std::endl;
//     std::ostringstream dnsCmd;
//     dnsCmd << "netsh interface ip set dns \"" << adapterName << "\" static 8.8.8.8";
//     executeCommand(dnsCmd.str());

//     std::cout << "[SUCCESS] Client mode configured with default route via VPN" << std::endl;
//     return true;
// }

// std::string TUNInterface::getDefaultGateway() {
//     ULONG bufferSize = 15000;
//     PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

//     if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
//         free(pAdapterInfo);
//         pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
//     }

//     std::string gateway;
//     if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR) {
//         PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
//         while (pAdapter) {
//             if (pAdapter->GatewayList.IpAddress.String[0] != '0') {
//                 gateway = pAdapter->GatewayList.IpAddress.String;
//                 break;
//             }
//             pAdapter = pAdapter->Next;
//         }
//     }

//     free(pAdapterInfo);
//     return gateway;
// }

// std::string TUNInterface::getDefaultInterface() {
//     return interfaceName;
// }

// bool TUNInterface::executeCommand(const std::string& cmd) {
//     std::cout << "[CMD] " << cmd << std::endl;
//     int ret = system(cmd.c_str());
//     if (ret != 0) {
//         std::cerr << "[WARN] Command returned non-zero: " << ret << std::endl;
//     }
//     return (ret == 0);
// }

// int TUNInterface::readPacket(char* buffer, int maxSize) {
//     if (!isOpen.load() || tunFd < 0) return -1;

//     HANDLE handle = (HANDLE)(intptr_t)tunFd;
//     OVERLAPPED overlapped = {0};
//     overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

//     DWORD bytesRead = 0;
//     BOOL result = ReadFile(handle, buffer, maxSize, &bytesRead, &overlapped);

//     if (!result) {
//         if (GetLastError() == ERROR_IO_PENDING) {
//             DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 100);
//             if (waitResult == WAIT_OBJECT_0) {
//                 GetOverlappedResult(handle, &overlapped, &bytesRead, FALSE);
//             } else {
//                 CancelIo(handle);
//                 CloseHandle(overlapped.hEvent);
//                 return 0;
//             }
//         } else {
//             CloseHandle(overlapped.hEvent);
//             return -1;
//         }
//     }

//     CloseHandle(overlapped.hEvent);

//     if (bytesRead > 0) {
//         bytesReceived += bytesRead;
//         return bytesRead;
//     }

//     return 0;
// }

// int TUNInterface::writePacket(const char* buffer, int size) {
//     if (!isOpen.load() || tunFd < 0) return -1;
//     if (size <= 0) return 0;

//     HANDLE handle = (HANDLE)(intptr_t)tunFd;
//     OVERLAPPED overlapped = {0};
//     overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

//     DWORD bytesWritten = 0;
//     BOOL result = WriteFile(handle, buffer, size, &bytesWritten, &overlapped);

//     if (!result) {
//         if (GetLastError() == ERROR_IO_PENDING) {
//             DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 1000);
//             if (waitResult == WAIT_OBJECT_0) {
//                 GetOverlappedResult(handle, &overlapped, &bytesWritten, FALSE);
//             } else {
//                 CancelIo(handle);
//                 CloseHandle(overlapped.hEvent);
//                 return 0;
//             }
//         } else {
//             CloseHandle(overlapped.hEvent);
//             return -1;
//         }
//     }

//     CloseHandle(overlapped.hEvent);

//     if (bytesWritten > 0) {
//         bytesSent += bytesWritten;
//         return bytesWritten;
//     }

//     return 0;
// }

// bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
//     vpnIP = ip;
//     subnetMask = mask;

//     std::string adapterName = getAdapterFriendlyName();
//     std::ostringstream cmd;
//     cmd << "netsh interface ip set address \"" << adapterName
//         << "\" static " << vpnIP << " " << subnetMask;

//     return executeCommand(cmd.str());
// }

// bool TUNInterface::setRoutes() {
//     if (serverIP.empty()) return true;

//     std::ostringstream cmd;
//     cmd << "route add 0.0.0.0 mask 0.0.0.0 " << vpnIP;
//     return executeCommand(cmd.str());
// }

// void TUNInterface::close() {
//     if (isOpen.load() && tunFd >= 0) {
//         std::cout << "\n[INFO] ========== Closing TUN Interface ==========" << std::endl;

//         // Restore old gateway
//         std::ifstream gwFile("C:\\vpn_old_gateway.txt");
//         if (gwFile.is_open()) {
//             std::string oldGateway;
//             std::getline(gwFile, oldGateway);
//             gwFile.close();

//             if (!oldGateway.empty()) {
//                 std::cout << "[INFO] Restoring network configuration..." << std::endl;

//                 // Delete VPN routes
//                 executeCommand("route delete 0.0.0.0");
//                 executeCommand("route delete 10.8.0.0");

//                 // Restore default gateway
//                 std::ostringstream restoreCmd;
//                 restoreCmd << "route add 0.0.0.0 mask 0.0.0.0 " << oldGateway;
//                 executeCommand(restoreCmd.str());

//                 std::cout << "[INFO] Network configuration restored" << std::endl;
//             }

//             DeleteFileA("C:\\vpn_old_gateway.txt");
//         }

//         HANDLE handle = (HANDLE)(intptr_t)tunFd;
//         CloseHandle(handle);
//         tunFd = -1;
//         isOpen.store(false);

//         std::cout << "[SUCCESS] TAP adapter closed successfully" << std::endl;
//         std::cout << "[INFO] ===========================================\n" << std::endl;
//     }
// }

// void TUNInterface::resetStats() {
//     bytesReceived = 0;
//     bytesSent = 0;
// }
