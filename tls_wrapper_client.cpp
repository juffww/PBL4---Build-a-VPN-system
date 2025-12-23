#include "tls_wrapper_client.h"
#include <iostream>
#include <openssl/rand.h>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
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

#ifdef _WIN32
    // Windows: Set socket to blocking mode
    u_long mode = 0; // 0 = blocking
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        std::cerr << "[TLS] Failed to set blocking mode: " << WSAGetLastError() << "\n";
        return false;
    }
#else
    // Unix/macOS
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "[TLS] Failed to get socket flags\n";
        perror("fcntl F_GETFL");
        return false;
    }

    if (fcntl(socket, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        std::cerr << "[TLS] Failed to set blocking mode\n";
        perror("fcntl F_SETFL");
        return false;
    }
#endif

    std::cout << "[TLS] Socket set to blocking mode\n";

    ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[TLS] Failed to create SSL object\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_set_fd(ssl, socket) != 1) {
        std::cerr << "[TLS] Failed to set socket FD\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }

    std::cout << "[TLS] SSL object created, FD set: " << socket << "\n";

#ifdef _WIN32
    DWORD timeout = 10000; // 10 seconds in milliseconds
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        std::cerr << "[TLS] Failed to set receive timeout\n";
    }
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        std::cerr << "[TLS] Failed to set send timeout\n";
    }
#else
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "[TLS] Failed to set receive timeout\n";
        perror("setsockopt SO_RCVTIMEO");
    }
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "[TLS] Failed to set send timeout\n";
        perror("setsockopt SO_SNDTIMEO");
    }
#endif

    int ret;
    if (isServer) {
        std::cout << "[TLS] Starting server handshake...\n";
        ret = SSL_accept(ssl);
    } else {
        std::cout << "[TLS] Starting client handshake...\n";
        ret = SSL_connect(ssl);
    }

    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        std::cerr << "[TLS] " << (isServer ? "Accept" : "Connect")
                  << " failed with error: " << err << "\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }

    std::cout << "[TLS] Handshake successful (Cipher: " << SSL_get_cipher(ssl) << ")\n";

    if (!isServer) {
        std::cout << "[TLS] Waiting for server welcome message...\n";

#ifdef _WIN32
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);
        tv.tv_sec = 3;
        tv.tv_usec = 0;

        int selectRet = select(0, &readfds, nullptr, nullptr, &tv);
#else
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);
        tv.tv_sec = 3;
        tv.tv_usec = 0;

        int selectRet = select(socket + 1, &readfds, nullptr, nullptr, &tv);
#endif

        if (selectRet > 0) {
            char welcomeBuf[256];
            memset(welcomeBuf, 0, sizeof(welcomeBuf));
            int readBytes = SSL_read(ssl, welcomeBuf, sizeof(welcomeBuf) - 1);
            if (readBytes > 0) {
                welcomeBuf[readBytes] = '\0';
                std::cout << "[TLS] âœ“ Received: " << welcomeBuf << std::endl;

#ifdef _WIN32
                Sleep(100); // 100ms
#else
                usleep(100000);
#endif
            } else {
                int err = SSL_get_error(ssl, readBytes);
                std::cerr << "[TLS] âš  Welcome message read failed (SSL error: " << err << ")\n";
                if (readBytes == 0) {
                    std::cerr << "[TLS] Connection closed by server during welcome\n";
                    SSL_free(ssl);
                    ssl = nullptr;
                    return false;
                }
            }
        } else if (selectRet == 0) {
            std::cout << "[TLS] âš  No welcome message (timeout - may be OK)\n";
        } else {
            std::cerr << "[TLS] âš  Select error while waiting for welcome\n";
        }
    }

#ifdef _WIN32
    mode = 1; // 1 = non-blocking
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        std::cerr << "[TLS] Failed to restore non-blocking mode: " << WSAGetLastError() << "\n";
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }
    std::cout << "[TLS] âœ“ Socket restored to non-blocking mode\n";
#else
    int setFlags = flags | O_NONBLOCK;
    if (fcntl(socket, F_SETFL, setFlags) == -1) {
        std::cerr << "[TLS] Failed to restore non-blocking mode\n";
        perror("fcntl F_SETFL");
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }

    int currentFlags = fcntl(socket, F_GETFL, 0);
    if (currentFlags != -1 && (currentFlags & O_NONBLOCK)) {
        std::cout << "[TLS] âœ“ Socket restored to non-blocking mode for Qt\n";
    } else {
        std::cerr << "[TLS] âš  Non-blocking mode verification failed\n";
    }
#endif

    return true;
}

int TLSWrapper::send(const char* data, int len) {
    if (!ssl) return -1;

    int sent = SSL_write(ssl, data, len);
    if (sent <= 0) {
        int err = SSL_get_error(ssl, sent);
        if (err != SSL_ERROR_WANT_WRITE) {
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

        if (err != SSL_ERROR_WANT_READ &&
            err != SSL_ERROR_WANT_WRITE &&
            err != SSL_ERROR_ZERO_RETURN) {
            std::cerr << "[TLS] Read error: " << err << "\n";
        }
    }
    return received;
}

// void TLSWrapper::cleanup() {
//     if (ssl) {
//         SSL_shutdown(ssl);
//         SSL_free(ssl);
//         ssl = nullptr;
//     }
//     if (ctx) {
//         SSL_CTX_free(ctx);
//         ctx = nullptr;
//     }
// }
// Trong tls_wrapper_client.cpp

void TLSWrapper::cleanup() {
    if (ssl) {

        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

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
