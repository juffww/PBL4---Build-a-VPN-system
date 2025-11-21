// crypto_client.h - Thêm file mới này vào project
#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H

#include <vector>
#include <cstdint>

class CryptoClient {
public:
    // Encrypt with AES-256-GCM
    static bool Encrypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& tag);

    // Decrypt with AES-256-GCM
    static bool Decrypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& tag,
                        std::vector<uint8_t>& plaintext);

private:
    static constexpr int AES_KEY_SIZE = 32;  // 256-bit
    static constexpr int AES_IV_SIZE = 12;   // 96-bit for GCM
    static constexpr int GCM_TAG_SIZE = 16;  // 128-bit
};

#endif // CRYPTO_CLIENT_H
