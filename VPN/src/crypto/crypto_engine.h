#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @class CryptoEngine
 * @brief Chỉ cung cấp AES-256-GCM encryption/decryption
 * (X25519/ECDH đã được thay thế bằng TLS)
 */
class CryptoEngine {
public:
    static constexpr int AES_KEY_SIZE = 32;   // 256 bits
    static constexpr int AES_IV_SIZE = 12;    // 96 bits (GCM standard)
    static constexpr int GCM_TAG_SIZE = 16;   // 128 bits

    /**
     * @brief Mã hóa plaintext bằng AES-256-GCM
     */
    static bool Encrypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& tag);

    /**
     * @brief Giải mã ciphertext bằng AES-256-GCM
     */
    static bool Decrypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& tag,
                        std::vector<uint8_t>& plaintext);
};

#endif // CRYPTO_ENGINE_H