#include "tls_wrapper_client.h"
#include <iostream>
#include <openssl/rand.h>
#include <cstring>
#include <openssl/err.h> // Đừng quên include này

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h> // Cần cho fcntl
typedef int SOCKET;
#endif

TLSWrapper::TLSWrapper(bool server) : ctx(nullptr), ssl(nullptr), socket(-1), isServer(server) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD* method = isServer ? TLS_server_method() : TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "[TLS] Failed to create SSL context\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (!isServer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        std::cout << "[TLS] Client mode - certificate verification disabled\n";
    }
}

TLSWrapper::~TLSWrapper() {
    cleanup();
}

bool TLSWrapper::loadCertificates(const std::string& certFile, const std::string& keyFile) {
    if (!ctx) return false;
    if (!isServer) return true;

    if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[TLS] Failed to load certificate: " << certFile << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[TLS] Failed to load private key: " << keyFile << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[TLS] Private key does not match certificate\n";
        return false;
    }

    std::cout << "[TLS] Certificates loaded successfully\n";
    return true;
}

bool TLSWrapper::initTLS(SOCKET sock) {
    if (!ctx) {
        std::cerr << "[TLS] SSL context not initialized\n";
        return false;
    }

    socket = sock;

    // 1. CHUYỂN VỀ BLOCKING MODE (BẮT BUỘC ĐỂ HANDSHAKE)
#ifdef _WIN32
    u_long mode = 0; // 0 = blocking
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        std::cerr << "[TLS] Failed to set blocking mode: " << WSAGetLastError() << "\n";
        return false;
    }
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return false;
    }
    if (fcntl(socket, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL blocking");
        return false;
    }
#endif

    std::cout << "[TLS] Socket set to blocking mode for handshake\n";

    ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[TLS] Failed to create SSL object\n";
        return false;
    }

    if (SSL_set_fd(ssl, socket) != 1) {
        std::cerr << "[TLS] Failed to set socket FD\n";
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }

    // Set Timeout để tránh treo mãi mãi nếu server không phản hồi
#ifdef _WIN32
    DWORD timeout = 10000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    // 2. HANDSHAKE
    int ret;
    if (isServer) {
        ret = SSL_accept(ssl);
    } else {
        ret = SSL_connect(ssl);
    }

    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        std::cerr << "[TLS] Handshake failed: " << err << "\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }

    std::cout << "[TLS] Handshake successful\n";

    // 3. ĐỌC WELCOME MESSAGE (Tùy chọn)
    if (!isServer) {
        // Dùng select để peek xem có dữ liệu không
        fd_set readfds;
        struct timeval tv_sel;
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);
        tv_sel.tv_sec = 2; // Chờ tối đa 2 giây cho welcome
        tv_sel.tv_usec = 0;

        int selRet = select((int)socket + 1, &readfds, nullptr, nullptr, &tv_sel);
        if (selRet > 0) {
            char welcomeBuf[256];
            int readBytes = SSL_read(ssl, welcomeBuf, sizeof(welcomeBuf) - 1);
            if (readBytes > 0) {
                welcomeBuf[readBytes] = '\0';
                std::cout << "[TLS] Received: " << welcomeBuf << std::endl;
            }
        }
    }

    // 4. [QUAN TRỌNG] KHÔI PHỤC NON-BLOCKING CHO QT
    // Nếu không làm bước này, giao diện Client sẽ bị đơ.
#ifdef _WIN32
    mode = 1; // 1 = non-blocking
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        std::cerr << "[TLS] Failed to restore non-blocking mode\n";
        return false;
    }
#else
    if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL non-blocking");
        return false;
    }
#endif

    std::cout << "[TLS] Socket restored to NON-BLOCKING mode for Qt\n";
    return true;
}

int TLSWrapper::send(const char* data, int len) {
    if (!ssl) return -1;

    int sent = SSL_write(ssl, data, len);
    if (sent <= 0) {
        int err = SSL_get_error(ssl, sent);
        // Với Non-blocking socket, WANT_WRITE không phải là lỗi
        if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ) {
            std::cerr << "[TLS] Write error: " << err << "\n";
        }
    }
    return sent;
}

int TLSWrapper::recv(char* buffer, int len) {
    if (!ssl) return -1;

    int received = SSL_read(ssl, buffer, len);
    if (received <= 0) {
        int err = SSL_get_error(ssl, received);

        // Với Non-blocking socket, WANT_READ là bình thường (chưa có dữ liệu)
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            if (err != SSL_ERROR_ZERO_RETURN) { // Zero return là đóng kết nối sạch
                std::cerr << "[TLS] Read error: " << err << "\n";
            }
        }
    }
    return received;
}

void TLSWrapper::cleanup() {
    if (ssl) {
        // [QUAN TRỌNG] KHÔNG gọi SSL_shutdown() để tránh Crash
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
}

SSL* TLSWrapper::getSSL() const {
    return ssl;
}
