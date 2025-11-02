#include "tls_wrapper.h"
#include <iostream>
#include <openssl/rand.h>
#include <cstring>
#include <errno.h>

TLSWrapper::TLSWrapper(bool server) : ctx(nullptr), ssl(nullptr), socket(-1), isServer(server) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD* method = isServer ? TLS_server_method() : TLS_client_method();
    ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        std::cerr << "[TLS] Failed to create SSL context\n";
        ERR_print_errors_fp(stderr);
    }
    
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}

TLSWrapper::~TLSWrapper() {
    cleanup();
}

bool TLSWrapper::loadCertificates(const std::string& certFile, const std::string& keyFile) {
    if (!ctx) return false;
    
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
    socket = sock;
    ssl = SSL_new(ctx);
    
    if (!ssl) {
        std::cerr << "[TLS] Failed to create SSL object\n";
        return false;
    }
    
    SSL_set_fd(ssl, socket);
    
    int ret;
    if (isServer) {
        ret = SSL_accept(ssl);
    } else {
        ret = SSL_connect(ssl);
    }
    
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        std::cerr << "[TLS] " << (isServer ? "Accept" : "Connect") << " failed: " << err << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    std::cout << "[TLS] Handshake successful (Cipher: " << SSL_get_cipher(ssl) << ")\n";
    return true;
}

int TLSWrapper::send(const char* data, int len) {
    if (!ssl) return -1;
    
    int written = SSL_write(ssl, data, len);
    
    if (written <= 0) {
        int err = SSL_get_error(ssl, written);
        if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ) {
            std::cerr << "[TLS] Write error: " << err;
            if (err == SSL_ERROR_SYSCALL && errno != 0) {
                std::cerr << " (errno: " << errno << " - " << strerror(errno) << ")";
            }
            std::cerr << "\n";
            ERR_print_errors_fp(stderr);
        }
    }
    
    return written;
}

int TLSWrapper::recv(char* buffer, int len) {
    if (!ssl) return -1;
    
    int read = SSL_read(ssl, buffer, len);
    
    if (read <= 0) {
        int err = SSL_get_error(ssl, read);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            if (err == SSL_ERROR_ZERO_RETURN) {
            } else if (err == SSL_ERROR_SYSCALL && errno == 0) {
            } else {
                std::cerr << "[TLS] Read error: " << err;
                if (err == SSL_ERROR_SYSCALL && errno != 0) {
                    std::cerr << " (errno: " << errno << " - " << strerror(errno) << ")";
                }
                std::cerr << "\n";
            }
        }
    }
    
    return read;
}

void TLSWrapper::cleanup() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
}
