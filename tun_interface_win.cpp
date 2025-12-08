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

bool loadWintunDll() {
    if (g_wintunDll) return true;
    g_wintunDll = LoadLibraryW(L"wintun.dll");
    if (!g_wintunDll) return false;

    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(g_wintunDll, "WintunCreateAdapter");
    WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(g_wintunDll, "WintunCloseAdapter");
    WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(g_wintunDll, "WintunStartSession");
    WintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(g_wintunDll, "WintunEndSession");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunSendPacket");
    WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(g_wintunDll, "WintunGetReadWaitEvent");

    if (!WintunCreateAdapter || !WintunCloseAdapter || !WintunStartSession) {
        FreeLibrary(g_wintunDll);
        g_wintunDll = nullptr;
        return false;
    }
    return true;
}

HANDLE TUNInterface::getReadWaitEvent() const {
    return readWaitEvent;
}

bool TUNInterface::create() {
    if (!loadWintunDll()) return false;

    if (!g_adapter) {
        GUID guid = { 0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC} };
        g_adapter = WintunCreateAdapter(L"MyVPN", L"WinTun", &guid);
        if (!g_adapter) {
            std::cerr << "[WINTUN] Failed to create adapter. Error: " << GetLastError() << "\n";
            return false;
        }
    }

    if (g_session) {
        WintunEndSession(g_session);
        g_session = nullptr;
    }

    g_session = WintunStartSession(g_adapter, 0x400000);
    if (!g_session) return false;

    readWaitEvent = WintunGetReadWaitEvent(g_session);
    interfaceName = "MyVPN";
    isOpen.store(true);
    return true;
}

// Hàm lấy Index Adapter CHUẨN XÁC bằng API (Không dùng netsh)
std::string TUNInterface::getInterfaceIndex(const std::string& adapterName) {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    }

    DWORD dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    std::string index = "";

    if (dwRetVal == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            char friendlyName[256];
            size_t converted;
            wcstombs_s(&converted, friendlyName, pCurrAddresses->FriendlyName, 256);

            if (adapterName == friendlyName) {
                index = std::to_string(pCurrAddresses->IfIndex);
                break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    free(pAddresses);
    return index;
}

bool TUNInterface::configureClientMode() {
    if (!isOpen.load()) return false;

    setIPv6Status(false);

    std::string oldGateway = getDefaultGateway();
    if (oldGateway.empty() || oldGateway == "0.0.0.0") {
        std::vector<std::string> gwList = {"192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"};
        for(const auto& gw : gwList) {
            std::string cmd = "ping -n 1 -w 50 " + gw + " >nul 2>&1";
            if (system(cmd.c_str()) == 0) {
                oldGateway = gw;
                break;
            }
        }
        if (oldGateway.empty()) {
            std::cerr << "[TUN] CRITICAL: No physical gateway found!\n";
            return false;
        }
    }
    std::cout << "[TUN] Physical Gateway: " << oldGateway << "\n";

    std::ofstream bk("C:\\vpn_old_gateway.txt");
    bk << oldGateway;
    bk.close();

    std::ostringstream ipCmd;
    ipCmd << "netsh interface ip set address name=\"" << interfaceName
          << "\" source=static addr=" << vpnIP
          << " mask=" << subnetMask
          << " gateway=10.8.0.1"; // THÊM GATEWAY

    if (!executeCommand(ipCmd.str())) {
        std::cerr << "[TUN] Failed to set IP with gateway\n";
        return false;
    }

    std::cout << "[TUN] ✓ IP and Gateway configured\n";
    Sleep(2000);

    std::string idx = getInterfaceIndex(interfaceName);
    if (idx.empty()) {
        std::cerr << "[TUN] ERROR: Could not find adapter index\n";
        return false;
    }
    std::cout << "[TUN] MyVPN Index: " << idx << "\n";

    if (!serverIP.empty()) {
        executeCommand("route delete " + serverIP + " >nul 2>&1");
        std::string cmd = "route add " + serverIP + " mask 255.255.255.255 " + oldGateway + " metric 1";
        if (!executeCommand(cmd)) {
            std::cerr << "[TUN] Warning: Failed to add server route\n";
        } else {
            std::cout << "[TUN] ✓ Server bypass route added\n";
        }
    }

    std::string vpnGateway = "10.8.0.1";

    executeCommand("route delete 0.0.0.0 mask 128.0.0.0 >nul 2>&1");
    executeCommand("route delete 128.0.0.0 mask 128.0.0.0 >nul 2>&1");

    std::string r1 = "route add 0.0.0.0 mask 128.0.0.0 " + vpnGateway + " metric 1 IF " + idx;
    std::string r2 = "route add 128.0.0.0 mask 128.0.0.0 " + vpnGateway + " metric 1 IF " + idx;

    if (executeCommand(r1) && executeCommand(r2)) {
        std::cout << "[TUN] ✓ Internet routes via VPN added\n";
    } else {
        std::cerr << "[TUN] ✗ Failed to add VPN routes\n";
    }

    std::string dnsVPN = "netsh interface ip set dns name=\"" + interfaceName + "\" source=static addr=8.8.8.8 validate=no";
    executeCommand(dnsVPN);

    std::string dns2 = "netsh interface ip add dns name=\"" + interfaceName + "\" addr=8.8.4.4 index=2 validate=no";
    executeCommand(dns2);

    executeCommand("ipconfig /flushdns");

    std::cout << "[TUN] ✓ DNS configured\n";
    return true;
}

bool TUNInterface::configure(const std::string& ip, const std::string& mask, const std::string& server) {
    vpnIP = ip;
    subnetMask = mask;
    serverIP = server;
    return configureClientMode();
}

int TUNInterface::readPacket(char* buffer, int maxSize) {
    if (!isOpen.load() || !g_session) return -1;
    DWORD packetSize = 0;
    BYTE* packet = WintunReceivePacket(g_session, &packetSize);
    if (!packet) return 0;
    if (packetSize > (DWORD)maxSize) {
        WintunReleaseReceivePacket(g_session, packet);
        return -1;
    }
    memcpy(buffer, packet, packetSize);
    WintunReleaseReceivePacket(g_session, packet);
    if (packetSize > 0) bytesReceived += packetSize;
    return packetSize;
}

int TUNInterface::writePacket(const char* buffer, int size) {
    if (!isOpen.load() || !g_session) return -1;
    BYTE* packet = WintunAllocateSendPacket(g_session, size);
    if (!packet) return -1;
    memcpy(packet, buffer, size);
    WintunSendPacket(g_session, packet);
    bytesSent += size;
    return size;
}

void TUNInterface::close() {
    if (!isOpen.load()) return;
    std::cout << "[TUN] Restoring network...\n";

    executeCommand("route delete 0.0.0.0 mask 128.0.0.0 >nul 2>&1");
    executeCommand("route delete 128.0.0.0 mask 128.0.0.0 >nul 2>&1");
    if (!serverIP.empty()) executeCommand("route delete " + serverIP + " >nul 2>&1");

    DeleteFileA("C:\\vpn_old_gateway.txt");

    if (g_session) {
        WintunEndSession(g_session);
        g_session = nullptr;
    }
    isOpen.store(false);
}

void TUNInterface::setIPv6Status(bool enable) {
    std::string cmd = "powershell -Command \"Get-NetAdapterBinding -ComponentID ms_tcpip6 | Set-NetAdapterBinding -Enabled:" + std::string(enable ? "$true" : "$false") + "\" >nul 2>&1";
    system(cmd.c_str());
}

std::string TUNInterface::getDefaultGateway() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }

    std::string gw = "";
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->Type == MIB_IF_TYPE_ETHERNET || pAdapter->Type == IF_TYPE_IEEE80211) {
                std::string g = pAdapter->GatewayList.IpAddress.String;
                if (g != "0.0.0.0" && !g.empty()) {
                    gw = g;
                    break;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    return gw;
}

bool TUNInterface::executeCommand(const std::string& cmd) {
    return system(cmd.c_str()) == 0;
}

void TUNInterface::resetStats() { bytesReceived = 0; bytesSent = 0; }
void TUNInterface::shutdown() { close(); if(g_adapter) { WintunCloseAdapter(g_adapter); g_adapter=nullptr; } }

#endif
