#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H

#include <vector>
#include <cstdint>
#include <openssl/evp.h> // Cần include thư viện này để dùng EVP_CIPHER_CTX

class CryptoClient {
public:
    CryptoClient();  // Constructor: Khởi tạo Context
    ~CryptoClient(); // Destructor: Giải phóng Context

    // Khởi tạo ban đầu (nếu cần kiểm tra lỗi khi init)
    bool init();

    // KHÔNG còn là static nữa
    bool Encrypt(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 const uint8_t* plaintext, size_t plainlen, // Tối ưu Bottleneck #2 luôn: dùng con trỏ thay vì vector
                 std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& tag);

    bool Decrypt(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 const uint8_t* ciphertext, size_t cipherlen,
                 const std::vector<uint8_t>& tag,
                 std::vector<uint8_t>& plaintext);

private:
    // Đây là "chiếc xe" chúng ta mua 1 lần và dùng mãi
    EVP_CIPHER_CTX* encryptCtx;
    EVP_CIPHER_CTX* decryptCtx;

    static constexpr int AES_KEY_SIZE = 32;
    static constexpr int AES_IV_SIZE = 12;
    static constexpr int GCM_TAG_SIZE = 16;
};

#endif // CRYPTO_CLIENT_H
