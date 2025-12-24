#ifndef TLS_WRAPPER_CLIENT_H
#define TLS_WRAPPER_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

#ifdef _WIN32
    #include <winsock2.h>
    typedef int SOCKET;
#else
    typedef int SOCKET;
#endif

class TLSWrapper {
private:
    SSL_CTX* ctx;
    SSL* ssl;
    SOCKET socket;
    bool isServer;

public:
    TLSWrapper(bool server = true);
    ~TLSWrapper();
    
    // Server: Load certificate and private key
    bool loadCertificates(const std::string& certFile, const std::string& keyFile);
    
    // Initialize TLS connection
    bool initTLS(SOCKET sock);
    
    // Send/Receive over TLS
    int send(const char* data, int len);
    int recv(char* buffer, int len);
    
    // Get underlying SSL object
    SSL* getSSL() const;
    
    // Cleanup
    void cleanup();
};

#endif // TLS_WRAPPER_CLIENT_H
