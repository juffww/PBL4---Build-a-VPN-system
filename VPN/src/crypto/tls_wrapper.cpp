#include "tls_wrapper.h"
#include <iostream>
#include <openssl/rand.h>

TLSWrapper::TLSWrapper(bool server) : ctx(nullptr), ssl(nullptr), socket(-1), isServer(server) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD* method = isServer ? TLS_server_method() : TLS_client_method();
    ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        std::cerr << "[TLS] Failed to create SSL context\n";
        ERR_print_errors_fp(stderr);
    }
    
    // Set minimum TLS version to 1.2
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
    return SSL_write(ssl, data, len);
}

int TLSWrapper::recv(char* buffer, int len) {
    if (!ssl) return -1;
    return SSL_read(ssl, buffer, len);
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