// #include "tun_interface.h"
// #include <iostream>
// #include <sstream>
// #include <cstring>
// #include <fstream>
// #include <vector>

// #ifdef _WIN32
// #include <winsock2.h>
// #include <windows.h>
// #include <iphlpapi.h>
// #include <ws2tcpip.h>
// #pragma comment(lib, "iphlpapi.lib")
// #pragma comment(lib, "ws2_32.lib")

// #include "wintun.h"

// typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR, LPCWSTR, const GUID*);
// typedef BOOL (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE);
// typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE, DWORD);
// typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE);
// typedef BYTE* (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, DWORD*);
// typedef void (WINAPI *WINTUN_RELEASE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE*);
// typedef BYTE* (WINAPI *WINTUN_ALLOCATE_PACKET_FUNC)(WINTUN_SESSION_HANDLE, DWORD);
// typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE, const BYTE*);
// typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE);

// static HMODULE g_wintunDll = nullptr;
// static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
// static WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;
// static WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
// static WINTUN_END_SESSION_FUNC WintunEndSession = nullptr;
// static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
// static WINTUN_RELEASE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;
// static WINTUN_ALLOCATE_PACKET_FUNC WintunAllocateSendPacket = nullptr;
// static WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
// static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent = nullptr;

// static WINTUN_ADAPTER_HANDLE g_adapter = nullptr;
// static WINTUN_SESSION_HANDLE g_session = nullptr;

// #endif

// TUNInterface::TUNInterface(const std::string& name)
//     : interfaceName(name), isOpen(false), tunFd(-1),
//     vpnIP(""), subnetMask(""), serverIP(""),
//     bytesReceived(0), bytesSent(0) {
// }

// TUNInterface::~TUNInterface() {
//     close();
// }

// #ifdef _WIN32

// bool loadWintunDll() {
//     if (g_wintunDll) return true;

//     g_wintunDll = LoadLibraryW(L"wintun.dll");

//     if (!g_wintunDll) {
//         std::cerr << "[WINTUN] Failed to load wintun.dll: " << GetLastError() << std::endl;
//         return false;
//     }

//     WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(g_wintunDll, "WintunCreateAdapter");
//     WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(g_wintunDll, "WintunCloseAdapter");
//     WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(g_wintunDll, "WintunStartSession");
//     WintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(g_wintunDll, "WintunEndSession");
//     WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunReceivePacket");
//     WintunReleaseReceivePacket = (WINTUN_RELEASE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunReleaseReceivePacket");
//     WintunAllocateSendPacket = (WINTUN_ALLOCATE_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunAllocateSendPacket");
//     WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(g_wintunDll, "WintunSendPacket");
//     WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(g_wintunDll, "WintunGetReadWaitEvent");

//     if (!WintunCreateAdapter || !WintunCloseAdapter || !WintunStartSession ||
//         !WintunEndSession || !WintunReceivePacket || !WintunReleaseReceivePacket ||
//         !WintunAllocateSendPacket || !WintunSendPacket) {
//         std::cerr << "[WINTUN] Failed to load WinTun functions\n";
//         FreeLibrary(g_wintunDll);
//         g_wintunDll = nullptr;
//         return false;
//     }

//     std::cout << "[WINTUN] ✓ DLL loaded successfully\n";
//     return true;
// }

// HANDLE TUNInterface::getReadWaitEvent() const {
//     return readWaitEvent;
// }

// bool TUNInterface::create() {
//     if (!loadWintunDll()) {
//         std::cerr << "[WINTUN] Failed to load WinTun library\n";
//         return false;
//     }

//     if (!g_adapter) {
//         GUID guid = { 0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC} };

//         g_adapter = WintunCreateAdapter(L"MyVPN", L"WinTun", &guid);

//         if (!g_adapter) {
//             DWORD err = GetLastError();
//             std::cerr << "[WINTUN] Failed to create/open adapter: " << err << std::endl;
//             return false;
//         }
//         std::cout << "[WINTUN] ✓ Adapter created/opened\n";
//     }

//     if (g_session) {
//         WintunEndSession(g_session);
//         g_session = nullptr;
//     }

//     g_session = WintunStartSession(g_adapter, 0x400000);
//     readWaitEvent = WintunGetReadWaitEvent(g_session);
//     if (!g_session) {
//         std::cerr << "[WINTUN] Failed to start session: " << GetLastError() << std::endl;
//         return false;
//     }

//     std::cout << "[WINTUN] ✓ Session started\n";
//     interfaceName = "MyVPN";
//     isOpen.store(true);
//     return true;
// }

// bool TUNInterface::configure(const std::string& ip, const std::string& mask,
//                              const std::string& server) {
//     vpnIP = ip;
//     subnetMask = mask;
//     serverIP = server;

//     return configureClientMode();
// }

// bool TUNInterface::configureClientMode() {
//     if (!isOpen.load()) return false;

//     setIPv6Status(false);

//     // 1. Lấy Gateway thực tế hiện tại
//     std::string oldGateway = getDefaultGateway();
//     if (oldGateway.empty() || oldGateway == "0.0.0.0") {
//         std::cerr << "[TUN] Error: Could not detect physical Gateway. Internet may be unstable.\n";
//         // Cố gắng đoán gateway (fallback)
//         std::vector<std::string> commonGateways = {"192.168.1.1", "192.168.0.1", "10.0.0.1"};
//         for (const auto& gw : commonGateways) {
//             std::ostringstream testCmd;
//             testCmd << "ping -n 1 -w 100 " << gw << " >nul 2>&1";
//             if (executeCommand(testCmd.str())) {
//                 oldGateway = gw;
//                 break;
//             }
//         }
//         if (oldGateway.empty()) return false; // Không tìm thấy gateway thì không thể tiếp tục an toàn
//     }
//     std::cout << "[TUN] Physical Gateway: " << oldGateway << std::endl;

//     // Lưu gateway cũ để restore sau này (quan trọng)
//     std::ostringstream saveCmd;
//     saveCmd << "echo " << oldGateway << " > C:\\vpn_old_gateway.txt";
//     executeCommand(saveCmd.str());

//     // 2. Cấu hình IP cho TAP adapter
//     std::ostringstream ipCmd;
//     ipCmd << "netsh interface ip set address name=\"" << interfaceName
//           << "\" source=static addr=" << vpnIP
//           << " mask=" << subnetMask;

//     if (!executeCommand(ipCmd.str())) {
//         std::cerr << "[TUN] Failed to set IP config\n";
//         return false;
//     }
//     Sleep(500); // Đợi Windows áp dụng IP

//     std::string interfaceIndex = getInterfaceIndex(interfaceName);
//     if (interfaceIndex.empty()) {
//         std::cerr << "[TUN] Warning: Cannot get interface index, routing might fail.\n";
//         // Vẫn thử tiếp tục, Windows có thể tự chọn
//     }

//     // 3. QUAN TRỌNG: Bảo vệ kết nối tới VPN Server thật
//     // Route này ĐẢM BẢO gói tin mã hóa UDP gửi tới Server (42.118...) đi qua card mạng thật
//     if (!serverIP.empty()) {
//         // Xóa route cũ tới server (nếu có) để tránh conflict
//         executeCommand("route delete " + serverIP + " >nul 2>&1");

//         std::ostringstream serverRouteCmd;
//         // Thêm route: Đến ServerIP -> đi qua OldGateway
//         serverRouteCmd << "route add " << serverIP << " mask 255.255.255.255 " << oldGateway << " metric 1";
//         if (!executeCommand(serverRouteCmd.str())) {
//             std::cerr << "[TUN] Failed to add route to VPN Server IP\n";
//             return false;
//         }
//         std::cout << "[TUN] Protected route to VPN Server (" << serverIP << ") via " << oldGateway << "\n";
//     }

//     // 4. Định tuyến toàn bộ traffic qua VPN (Thay vì xóa 0.0.0.0)
//     // Kỹ thuật: Thêm 2 route 0.0.0.0/1 và 128.0.0.0/1 trỏ về 10.8.0.1 (hoặc Gateway ảo)
//     // Cách này override default route mà không cần xóa nó.

//     // Lưu ý: Với WinTun/TAP, gateway của route thường là IP của chính nó hoặc IP gateway ảo (thường là .1)
//     // Ở đây Client IP là 10.8.0.2, ta trỏ gateway về 10.8.0.1 (Server VPN IP trong tunnel)

//     std::string vpnGateway = "10.8.0.1";

//     std::ostringstream route1, route2;
//     // Nửa đầu internet: 0.0.0.0 - 127.255.255.255
//     route1 << "route add 0.0.0.0 mask 128.0.0.0 " << vpnGateway;
//     if (!interfaceIndex.empty()) route1 << " IF " << interfaceIndex;

//     // Nửa sau internet: 128.0.0.0 - 255.255.255.255
//     route2 << "route add 128.0.0.0 mask 128.0.0.0 " << vpnGateway;
//     if (!interfaceIndex.empty()) route2 << " IF " << interfaceIndex;

//     executeCommand(route1.str());
//     executeCommand(route2.str());

//     std::cout << "[TUN] Redirected Internet traffic via VPN (Split 0/1 & 128/1)\n";

//     // 5. DNS
//     std::ostringstream dnsCmd;
//     dnsCmd << "netsh interface ip set dns name=\"" << interfaceName
//            << "\" source=static addr=8.8.8.8";
//     executeCommand(dnsCmd.str());
//     executeCommand("ipconfig /flushdns");

//     return true;
// }

// int TUNInterface::readPacket(char* buffer, int maxSize) {
//     if (!isOpen.load() || !g_session) return -1;

//     DWORD packetSize = 0;
//     BYTE* packet = WintunReceivePacket(g_session, &packetSize);

//     if (!packet) {
//         DWORD err = GetLastError();
//         if (err == ERROR_NO_MORE_ITEMS) {
//             // No packets available - this is normal
//             return 0;
//         }
//         return -1;
//     }

//     // WinTun returns RAW IP packets (no Ethernet header)
//     if (packetSize > (DWORD)maxSize) {
//         WintunReleaseReceivePacket(g_session, packet);
//         return -1;
//     }

//     memcpy(buffer, packet, packetSize);
//     WintunReleaseReceivePacket(g_session, packet);

//     if (packetSize > 0) {
//         bytesReceived += packetSize;
//     }

//     return packetSize;
// }

// int TUNInterface::writePacket(const char* buffer, int size) {
//     if (!isOpen.load() || !g_session || size <= 0) return -1;

//     BYTE* packet = WintunAllocateSendPacket(g_session, size);

//     if (!packet) {
//         return -1;
//     }

//     memcpy(packet, buffer, size);
//     WintunSendPacket(g_session, packet);

//     bytesSent += size;
//     return size;
// }

// void TUNInterface::close() {
//     if (!isOpen.load()) return;

//     std::cout << "[TUN] Stopping session..." << std::endl;

//     std::cout << "[TUN] Cleaning up interface..." << std::endl;

//     setIPv6Status(true);

//     std::ifstream gwFile("C:\\vpn_old_gateway.txt");
//     std::string oldGateway;
//     if (gwFile.is_open()) {
//         std::getline(gwFile, oldGateway);
//         gwFile.close();

//         if (!oldGateway.empty()) {
//             executeCommand("route delete 0.0.0.0");

//             std::ostringstream restoreCmd;
//             restoreCmd << "route add 0.0.0.0 mask 0.0.0.0 " << oldGateway << " metric 1";
//             executeCommand(restoreCmd.str());
//         }

//         DeleteFileA("C:\\vpn_old_gateway.txt");
//     }

//     if (!serverIP.empty()) {
//         executeCommand("route delete " + serverIP);
//     }

//     // Close WinTun session and adapter
//     if (g_session) {
//         WintunEndSession(g_session);
//         g_session = nullptr;
//     }

//     isOpen.store(false);
//     std::cout << "[TUN] ✓ Cleanup complete\n";
// }

// void TUNInterface::setIPv6Status(bool enable) {
//     std::string status = enable ? "enabled" : "disabled";
//     std::string cmd = "powershell -Command \"Get-NetAdapterBinding -ComponentID ms_tcpip6 | "
//                       "Set-NetAdapterBinding -Enabled:" + std::string(enable ? "$true" : "$false") + "\"";
//     executeCommand(cmd);
// }

// std::string TUNInterface::getInterfaceIndex(const std::string& adapterName) {
//     FILE* pipe = _popen(("netsh interface ipv4 show interfaces | findstr \"" + adapterName + "\"").c_str(), "r");
//     if (!pipe) return "";

//     char buffer[256];
//     std::string result;
//     while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
//         result += buffer;
//     }
//     _pclose(pipe);

//     std::istringstream iss(result);
//     std::string idx;
//     iss >> idx;
//     return idx;
// }

// std::string TUNInterface::getDefaultGateway() {
//     ULONG bufferSize = 15000;
//     PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

//     if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
//         free(adapterInfo);
//         adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
//     }

//     std::string gateway;
//     if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
//         PIP_ADAPTER_INFO adapter = adapterInfo;
//         while (adapter) {
//             if (adapter->Type == MIB_IF_TYPE_ETHERNET || adapter->Type == IF_TYPE_IEEE80211) {
//                 std::string gw = adapter->GatewayList.IpAddress.String;
//                 if (gw != "0.0.0.0" && !gw.empty()) {
//                     gateway = gw;
//                     break;
//                 }
//             }
//             adapter = adapter->Next;
//         }
//     }

//     free(adapterInfo);
//     return gateway;
// }

// bool TUNInterface::executeCommand(const std::string& cmd) {
//     return system(cmd.c_str()) == 0;
// }

// bool TUNInterface::setIP(const std::string& ip, const std::string& mask) {
//     vpnIP = ip;
//     subnetMask = mask;
//     std::ostringstream cmd;
//     cmd << "netsh interface ip set address name=\"" << interfaceName
//         << "\" static " << vpnIP << " " << subnetMask;
//     return executeCommand(cmd.str());
// }

// void TUNInterface::resetStats() {
//     bytesReceived = 0;
//     bytesSent = 0;
// }

// void TUNInterface::shutdown() {
//     close();

//     if (g_adapter) {
//         WintunCloseAdapter(g_adapter);
//         g_adapter = nullptr;
//         std::cout << "[WINTUN] Adapter destroyed\n";
//     }
// }

// #endif

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

// --- WINTUN DEFINITIONS ---
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
            // Convert WideChar FriendlyName to String
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

    // 1. Detect Gateway
    std::string oldGateway = getDefaultGateway();
    if (oldGateway.empty() || oldGateway == "0.0.0.0") {
        // Fallback detection
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

    // Backup gateway
    std::ofstream bk("C:\\vpn_old_gateway.txt");
    bk << oldGateway;
    bk.close();

    // 2. Set IP
    std::ostringstream ipCmd;
    ipCmd << "netsh interface ip set address name=\"" << interfaceName
          << "\" source=static addr=" << vpnIP << " mask=" << subnetMask;
    executeCommand(ipCmd.str());
    Sleep(1000); // Wait for IP application

    // 3. Get Correct Interface Index
    std::string idx = getInterfaceIndex(interfaceName);
    if (idx.empty()) {
        std::cerr << "[TUN] ERROR: Could not find adapter index for MyVPN\n";
        return false;
    }
    std::cout << "[TUN] MyVPN Index: " << idx << "\n";

    // 4. Specific Route to VPN Server (Bypass VPN)
    if (!serverIP.empty()) {
        executeCommand("route delete " + serverIP + " >nul 2>&1");
        std::string cmd = "route add " + serverIP + " mask 255.255.255.255 " + oldGateway + " metric 1";
        if (!executeCommand(cmd)) std::cerr << "[TUN] Failed to add server route\n";
    }

    // 5. Redirect Internet (Split 0/1 + 128/1)
    std::string vpnGateway = "10.8.0.1"; // Default gateway inside tunnel

    // Clean old routes just in case
    executeCommand("route delete 0.0.0.0 mask 128.0.0.0 >nul 2>&1");
    executeCommand("route delete 128.0.0.0 mask 128.0.0.0 >nul 2>&1");

    // Add new routes with specific Interface Index
    std::string r1 = "route add 0.0.0.0 mask 128.0.0.0 " + vpnGateway + " metric 1 IF " + idx;
    std::string r2 = "route add 128.0.0.0 mask 128.0.0.0 " + vpnGateway + " metric 1 IF " + idx;

    if (executeCommand(r1) && executeCommand(r2)) {
        std::cout << "[TUN] âœ“ Routing table updated (Traffic -> VPN)\n";
    } else {
        std::cerr << "[TUN] âš  Failed to add VPN routes. Run as Admin?\n";
    }

    // 6. DNS
    std::string dns = "netsh interface ip set dns name=\"" + interfaceName + "\" source=static addr=8.8.8.8";
    executeCommand(dns);
    executeCommand("ipconfig /flushdns");

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

    // Restore default gateway priority if needed, but usually deleting overrides is enough
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
