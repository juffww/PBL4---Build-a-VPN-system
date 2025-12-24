#include "tls_wrapper_client.h"
#include <iostream>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

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
    if (!isServer) return true;  // Client không cần cert

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

    // ✅ macOS: Set timeout (struct timeval, không cast về const char*)
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

    // ✅ CRITICAL: Đợi và đọc welcome message TRƯỚC KHI chuyển sang non-blocking
    if (!isServer) {
        std::cout << "[TLS] Waiting for server welcome message...\n";

        // Đợi tối đa 3 giây để có dữ liệu
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);
        tv.tv_sec = 3;
        tv.tv_usec = 0;

        int selectRet = select(socket + 1, &readfds, nullptr, nullptr, &tv);
        if (selectRet > 0) {
            // Có dữ liệu - đọc ngay trong chế độ blocking
            char welcomeBuf[256];
            memset(welcomeBuf, 0, sizeof(welcomeBuf));
            int readBytes = SSL_read(ssl, welcomeBuf, sizeof(welcomeBuf) - 1);
            if (readBytes > 0) {
                welcomeBuf[readBytes] = '\0';
                std::cout << "[TLS] ✓ Received: " << welcomeBuf << std::endl;

                // ✅ CRITICAL: Đợi thêm 100ms để đảm bảo server xử lý xong
                usleep(100000);
            } else {
                int err = SSL_get_error(ssl, readBytes);
                std::cerr << "[TLS] ⚠ Welcome message read failed (SSL error: " << err << ")\n";
                if (readBytes == 0) {
                    std::cerr << "[TLS] Connection closed by server during welcome\n";
                    SSL_free(ssl);
                    ssl = nullptr;
                    return false;
                }
            }
        } else if (selectRet == 0) {
            std::cout << "[TLS] ⚠ No welcome message (timeout - may be OK)\n";
        } else {
            std::cerr << "[TLS] ⚠ Select error while waiting for welcome\n";
            perror("select");
        }
    }

    // ✅ BÂY GIỜ MỚI chuyển sang non-blocking - với error handling tốt hơn
    int setFlags = flags | O_NONBLOCK;
    if (fcntl(socket, F_SETFL, setFlags) == -1) {
        std::cerr << "[TLS] Failed to restore non-blocking mode\n";
        perror("fcntl F_SETFL");
        SSL_free(ssl);
        ssl = nullptr;
        return false;
    }

    // ✅ Verify non-blocking mode đã được set
    int currentFlags = fcntl(socket, F_GETFL, 0);
    if (currentFlags != -1 && (currentFlags & O_NONBLOCK)) {
        std::cout << "[TLS] ✓ Socket restored to non-blocking mode for Qt\n";
    } else {
        std::cerr << "[TLS] ⚠ Non-blocking mode verification failed\n";
    }

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

        // ✅ Không log WANT_READ (bình thường)
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            std::cerr << "[TLS] Read error: " << err << "\n";
        }
    }
    return received;
}

// Thay thế cleanup() trong tls_wrapper_client.cpp

void TLSWrapper::cleanup() {
    // ✅ CRITICAL: Kiểm tra đã cleanup chưa để tránh double-free
    if (!ssl && !ctx) {
        return;  // Already cleaned up
    }

    if (ssl) {
        // Quiet shutdown - không đợi response từ peer
        SSL_set_quiet_shutdown(ssl, 1);
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);

        // Shutdown connection
        // int ret = SSL_shutdown(ssl);
        // if (ret == 0) {
        //     // First shutdown sent close_notify, call again to receive peer's
        //     SSL_shutdown(ssl);
        // }

        // Free SSL object
        SSL_free(ssl);
        ssl = nullptr;
    }

    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }

    socket = -1;

    std::cout << "[TLS] Cleanup completed\n";
}

SSL* TLSWrapper::getSSL() const {
    return ssl;
}
