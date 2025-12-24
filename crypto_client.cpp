#include "crypto_client.h"
#include <openssl/err.h>
#include <iostream>
#include <cstring> // cho memcpy nếu cần

CryptoClient::CryptoClient() {
    encryptCtx = EVP_CIPHER_CTX_new();
    decryptCtx = EVP_CIPHER_CTX_new();

    if (!encryptCtx || !decryptCtx) {
        std::cerr << "[CRYPTO] Failed to allocate cipher contexts\n";
    }
}

CryptoClient::~CryptoClient() {
    if (encryptCtx) EVP_CIPHER_CTX_free(encryptCtx);
    if (decryptCtx) EVP_CIPHER_CTX_free(decryptCtx);
}

bool CryptoClient::init() {
    return (encryptCtx != nullptr && decryptCtx != nullptr);
}

bool CryptoClient::Encrypt(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const uint8_t* plaintext, size_t plainlen,
                           std::vector<uint8_t>& ciphertext,
                           std::vector<uint8_t>& tag) {
    if (!encryptCtx) return false;
    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE) {
        std::cerr << "[CRYPTO] Invalid key or IV size\n";
        return false;
    }

    // Reset context để tái sử dụng an toàn
    EVP_CIPHER_CTX_reset(encryptCtx);

    // Dự phòng kích thước output (plaintext + block size có thể dôi ra)
    ciphertext.resize(plainlen + 16);
    tag.resize(GCM_TAG_SIZE);

    int len = 0, cipherLen = 0;

    // 1. Init với thuật toán GCM
    if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;

    // 2. Set IV length
    if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) return false;

    // 3. Init Key và IV
    if (EVP_EncryptInit_ex(encryptCtx, nullptr, nullptr, key.data(), iv.data()) != 1) return false;

    // 4. Update dữ liệu (mã hóa)
    if (EVP_EncryptUpdate(encryptCtx, ciphertext.data(), &len, plaintext, plainlen) != 1) return false;
    cipherLen = len;

    // 5. Finalize (tính toán tag, GCM không có padding nên thường len=0 ở bước này)
    if (EVP_EncryptFinal_ex(encryptCtx, ciphertext.data() + len, &len) != 1) return false;
    cipherLen += len;

    // 6. Lấy Tag
    if (EVP_CIPHER_CTX_ctrl(encryptCtx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1) return false;

    // Resize lại kích thước chuẩn xác
    ciphertext.resize(cipherLen);
    return true;
}

bool CryptoClient::Decrypt(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const uint8_t* ciphertext, size_t cipherlen,
                           const std::vector<uint8_t>& tag,
                           std::vector<uint8_t>& plaintext) {
    if (!decryptCtx) return false;
    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE || tag.size() != GCM_TAG_SIZE) {
        std::cerr << "[CRYPTO] Invalid sizes for decryption\n";
        return false;
    }

    EVP_CIPHER_CTX_reset(decryptCtx);

    plaintext.resize(cipherlen);
    int len = 0, plainLen = 0;

    if (EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) return false;
    if (EVP_DecryptInit_ex(decryptCtx, nullptr, nullptr, key.data(), iv.data()) != 1) return false;

    if (EVP_DecryptUpdate(decryptCtx, plaintext.data(), &len, ciphertext, cipherlen) != 1) return false;
    plainLen = len;

    // Set expected tag for verification
    if (EVP_CIPHER_CTX_ctrl(decryptCtx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag.data()) != 1) return false;

    // Finalize and verify tag
    int ret = EVP_DecryptFinal_ex(decryptCtx, plaintext.data() + len, &len);

    if (ret > 0) {
        plainLen += len;
        plaintext.resize(plainLen);
        return true;
    } else {
        // Decryption failed (tag mismatch usually)
        return false;
    }
}
