#include "tun_interface.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <fstream>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "wintun.h"

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR, LPCWSTR, const GUID*);
typedef BOOL (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);
typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);
typedef BYTE* (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, DWORD*);
typedef void (WINAPI *WINTUN_RELEASE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE*);
typedef BYTE* (WINAPI *WINTUN_ALLOCATE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, DWORD);
typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE*);
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE);

// Global WinTun function pointers
static HMODULE g_wintunDll = nullptr;
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
static WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;
static WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
static WINTUN_END_SESSION_FUNC WintunEndSession = nullptr;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
static WINTUN_RELEASE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;
static WINTUN_ALLOCATE_PACKET_FUNC WintunAllocateSendPacket = nullptr;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent = nullptr;

// WinTun handles
static WINTUN_ADAPTER_HANDLE g_adapter = nullptr;
static WINTUN_SESSION_HANDLE g_session = nullptr;

#endif

TUNInterface::TUNInterface(const std::string& name)
    : interfaceName(name), isOpen(false), tunFd(-1),
    vpnIP(""), subnetMask(""), serverIP(""),
    bytesReceived(0), bytesSent(0) {
}

TUNInterface::~TUNInterface() {
    close();
}

#ifdef _WIN32

// Load WinTun DLL
bool loadWintunDll() {
    if (g_wintunDll) return true; // Already loaded

    // Try to load from current directory
    g_wintunDll = LoadLibraryW(L"wintun.dll");

    if (!g_wintunDll) {
        std::cerr << "[WINTUN] Failed to load wintun.dll: " << GetLastError() << std::endl;
        return false;
    }

    // Load all function pointers
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(g_wintunDll, "WintunCreateAdapter");
    WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(g_wintunDll, "WintunCloseAdapter");
    WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(g_wintunDll, "WintunStartSession");
    WintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(g_wintunDll, "WintunEndSession");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunSendPacket");
    WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(g_wintunDll, "WintunGetReadWaitEvent");

    if (!WintunCreateAdapter || !WintunCloseAdapter || !WintunStartSession ||
        !WintunEndSession || !WintunReceivePacket || !WintunReleaseReceivePacket ||
        !WintunAllocateSendPacket || !WintunSendPacket) {
        std::cerr << "[WINTUN] Failed to load WinTun functions\n";
        FreeLibrary(g_wintunDll);
        g_wintunDll = nullptr;
        return false;
    }

    std::cout << "[WINTUN] ✓ DLL loaded successfully\n";
    return true;
}

bool TUNInterface::create() {
    if (isOpen.load()) return true;

    // Load WinTun DLL
    if (!loadWintunDll()) {
        std::cerr << "[WINTUN] Failed to load WinTun library\n";
        return false;
    }

    // Create WinTun adapter
    GUID guid = { 0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC} };

    g_adapter = WintunCreateAdapter(L"MyVPN", L"WinTun", &guid);

    if (!g_adapter) {
        DWORD err = GetLastError();
        std::cerr << "[WINTUN] Failed to create adapter: " << err << std::endl;
        return false;
    }

    std::cout << "[WINTUN] ✓ Adapter created\n";

    // Start WinTun session with 0x400000 ring capacity (4MB)
    g_session = WintunStartSession(g_adapter, 0x400000);

    if (!g_session) {
        std::cerr << "[WINTUN] Failed to start session: " << GetLastError() << std::endl;
        WintunCloseAdapter(g_adapter);
        g_adapter = nullptr;
        return false;
    }

    std::cout << "[WINTUN] ✓ Session started\n";

    interfaceName = "MyVPN";
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

    setIPv6Status(false);

    std::string oldGateway = getDefaultGateway();

    if (oldGateway.empty() || oldGateway == "0.0.0.0" || oldGateway == "10.8.0.1") {
        std::cout << "[TUN] Warning: Could not detect real gateway\n";
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

    std::cout << "[TUN] Old gateway (saved): " << oldGateway << std::endl;

    Sleep(500);

    // Configure IP address using netsh
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

    std::string interfaceIndex = getInterfaceIndex(interfaceName);
    if (interfaceIndex.empty()) {
        std::cerr << "[TUN] ✗ Cannot get interface index\n";
        interfaceIndex = "16";
    }

    // Protect server route
    if (!serverIP.empty() && !oldGateway.empty() && oldGateway != "0.0.0.0") {
        std::ostringstream saveCmd;
        saveCmd << "echo " << oldGateway << " > C:\\vpn_old_gateway.txt";
        executeCommand(saveCmd.str());

        executeCommand("route delete " + serverIP + " >nul 2>&1");
        Sleep(200);

        std::ostringstream serverRouteCmd;
        serverRouteCmd << "route add " << serverIP << " mask 255.255.255.255 " << oldGateway;
        if (executeCommand(serverRouteCmd.str())) {
            std::cout << "[TUN] ✓ Server route protected\n";
        }
    }

    Sleep(500);

    // Add default route through VPN
    executeCommand("route delete 0.0.0.0 >nul 2>&1");
    Sleep(200);

    std::ostringstream defaultRouteCmd;
    defaultRouteCmd << "route add 0.0.0.0 mask 0.0.0.0 10.8.0.1 IF " << interfaceIndex;

    if (executeCommand(defaultRouteCmd.str())) {
        std::cout << "[TUN] ✓ Default route added\n";
    }

    // Configure DNS
    std::ostringstream dns1Cmd, dns2Cmd;
    dns1Cmd << "netsh interface ip set dns name=\"" << interfaceName
            << "\" source=static addr=8.8.8.8 register=none validate=no";
    dns2Cmd << "netsh interface ip add dns name=\"" << interfaceName
            << "\" addr=8.8.4.4 index=2 validate=no";

    executeCommand(dns1Cmd.str());
    executeCommand(dns2Cmd.str());

    // DNS leak protection
    std::ostringstream dnsRouteCmd;
    dnsRouteCmd << "route add 8.8.8.8 mask 255.255.255.255 10.8.0.1 metric 1 IF " << interfaceIndex;
    executeCommand(dnsRouteCmd.str());

    std::cout << "[TUN] ✓ DNS configured\n";

    executeCommand("ipconfig /flushdns");

    std::cout << "[TUN] ✓ Client mode fully configured\n";
    return true;
}

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load() || !g_session) return -1;

    DWORD packetSize = 0;
    BYTE* packet = WintunReceivePacket(g_session, &packetSize);

    if (!packet) {
        DWORD err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) {
            // No packets available - this is normal
            return 0;
        }
        return -1;
    }

    // WinTun returns RAW IP packets (no Ethernet header)
    if (packetSize > (DWORD)maxSize) {
        WintunReleaseReceivePacket(g_session, packet);
        return -1;
    }

    memcpy(buffer, packet, packetSize);
    WintunReleaseReceivePacket(g_session, packet);

    if (packetSize > 0) {
        bytesReceived += packetSize;
    }

    return packetSize;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load() || !g_session || size <= 0) return -1;

    // WinTun expects RAW IP packets (no Ethernet header)
    BYTE* packet = WintunAllocateSendPacket(g_session, size);

    if (!packet) {
        return -1;
    }

    memcpy(packet, buffer, size);
    WintunSendPacket(g_session, packet);

    bytesSent += size;
    return size;
}

void TUNInterface::close() {
    if (!isOpen.load()) return;

    std::cout << "[TUN] Cleaning up interface..." << std::endl;

    setIPv6Status(true);

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
            executeCommand(restoreCmd.str());
        }

        DeleteFileA("C:\\vpn_old_gateway.txt");
    }

    if (!serverIP.empty()) {
        executeCommand("route delete " + serverIP);
    }

    // Close WinTun session and adapter
    if (g_session) {
        WintunEndSession(g_session);
        g_session = nullptr;
    }

    if (g_adapter) {
        WintunCloseAdapter(g_adapter);
        g_adapter = nullptr;
    }

    isOpen.store(false);
    std::cout << "[TUN] ✓ Cleanup complete\n";
}

// Helper functions remain the same
void TUNInterface::setIPv6Status(bool enable) {
    std::string status = enable ? "enabled" : "disabled";
    std::string cmd = "powershell -Command \"Get-NetAdapterBinding -ComponentID ms_tcpip6 | "
                      "Set-NetAdapterBinding -Enabled:" + std::string(enable ? "$true" : "$false") + "\"";
    executeCommand(cmd);
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

    std::istringstream iss(result);
    std::string idx;
    iss >> idx;
    return idx;
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
            if (adapter->Type == MIB_IF_TYPE_ETHERNET || adapter->Type == IF_TYPE_IEEE80211) {
                std::string gw = adapter->GatewayList.IpAddress.String;
                if (gw != "0.0.0.0" && !gw.empty()) {
                    gateway = gw;
                    break;
                }
            }
            adapter = adapter->Next;
        }
    }

    free(adapterInfo);
    return gateway;
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    return system(cmd.c_str()) == 0;
}

bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
    vpnIP = ip;
    subnetMask = mask;
    std::ostringstream cmd;
    cmd << "netsh interface ip set address name=\"" << interfaceName
        << "\" static " << vpnIP << " " << subnetMask;
    return executeCommand(cmd.str());
}

void TUNInterface::resetStats() {
    bytesReceived = 0;
    bytesSent = 0;
}

#endif // _WIN32
