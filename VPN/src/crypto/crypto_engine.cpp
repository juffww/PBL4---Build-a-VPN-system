#include "crypto_engine.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>

bool CryptoEngine::Encrypt(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& plaintext,
                           std::vector<uint8_t>& ciphertext,
                           std::vector<uint8_t>& tag) {
    
    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE) {
        std::cerr << "[CRYPTO] Invalid key or IV size\n";
        return false;
    }

    ciphertext.resize(plaintext.size());
    tag.resize(GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) 
        goto err;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) 
        goto err;
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) 
        goto err;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) 
        goto err;
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) 
        goto err;
    ciphertext_len += len;
    
    ciphertext.resize(ciphertext_len);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1) 
        goto err;

    EVP_CIPHER_CTX_free(ctx);
    return true;

err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool CryptoEngine::Decrypt(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& tag,
                           std::vector<uint8_t>& plaintext) {

    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE || tag.size() != GCM_TAG_SIZE) {
        std::cerr << "[CRYPTO] Invalid sizes\n";
        return false;
    }

    plaintext.resize(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0, plaintext_len = 0, ret;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) 
        goto err;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) 
        goto err;
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) 
        goto err;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) 
        goto err;
    plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag.data()) != 1) 
        goto err;

    ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true;
    }
    return false;

err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}