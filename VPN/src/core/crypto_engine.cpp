#include "crypto_engine.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <string>
#include <vector>
#include <iostream>

using namespace std;

static EVP_PKEY* pkey_from_pem(const string& pem, bool is_private) {
    BIO* bio = BIO_new_mem_buf(pem.c_str(), -1);
    if (!bio) {
        cerr << "CryptoEngine: BIO_new_mem_buf failed" << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (is_private) {
        pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    } else {
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    }

    if (!pkey) {
        cerr << "CryptoEngine: Failed to read PEM key" << endl;
        ERR_print_errors_fp(stderr);
    }
    else {
        if (EVP_PKEY_id(pkey) != EVP_PKEY_X25519) {
            cerr << "CryptoEngine: Key is not X25519 (ID: " << EVP_PKEY_id(pkey) << ")" << endl;
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        } 
    }

    BIO_free_all(bio);
    return pkey;
}

static string pem_from_pkey(EVP_PKEY* pkey, bool is_private) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "CryptoEngine: BIO_new failed" << endl;
        return "";
    }

    bool success;
    if (is_private) {
        success = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        success = PEM_write_bio_PUBKEY(bio, pkey);
    }

    if (!success) {
        cerr << "CryptoEngine: Failed to write PEM key" << endl;
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        return "";
    }

    char* pem_data;
    long len = BIO_get_mem_data(bio, &pem_data);
    string pem_str(pem_data, len);

    BIO_free_all(bio);
    return pem_str;
}

// --- CryptoEngine Implementation ---

bool CryptoEngine::GenerateKeyPair(std::string& private_key_pem, std::string& public_key_pem) {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) return false;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    private_key_pem = pem_from_pkey(pkey, true);
    public_key_pem = pem_from_pkey(pkey, false);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return !private_key_pem.empty() && !public_key_pem.empty();
}

bool CryptoEngine::DeriveSharedSecret(const std::string& private_key_pem,
                                      const std::string& public_key_pem,
                                      std::vector<uint8_t>& shared_key) {
    
    EVP_PKEY* priv_key = pkey_from_pem(private_key_pem, true);
    EVP_PKEY* peer_pub_key = pkey_from_pem(public_key_pem, false);

    if (!priv_key || !peer_pub_key) {
        if (priv_key) EVP_PKEY_free(priv_key);
        if (peer_pub_key) EVP_PKEY_free(peer_pub_key);
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return false;
    }

    // Khai báo TẤT CẢ biến TRƯỚC các label goto
    size_t raw_secret_len = 0;
    vector<uint8_t> raw_secret;
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* kctx = nullptr;
    const char* info = "vpn-aes-256-gcm-key";
    const char* salt = "vpn-hkdf-salt";
    OSSL_PARAM params[5];
    bool success = false;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        cerr << "DeriveSharedSecret: EVP_PKEY_derive_init failed" << endl;
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        cerr << "DeriveSharedSecret: EVP_PKEY_derive_set_peer failed" << endl;
        goto cleanup;
    }

    // 1. ECDH để lấy raw secret
    if (EVP_PKEY_derive(ctx, nullptr, &raw_secret_len) <= 0) {
        cerr << "DeriveSharedSecret: Failed to get raw secret length" << endl;
        goto cleanup;
    }

    raw_secret.resize(raw_secret_len);
    if (EVP_PKEY_derive(ctx, raw_secret.data(), &raw_secret_len) <= 0) {
        cerr << "DeriveSharedSecret: Failed to derive raw secret" << endl;
        goto cleanup;
    }

    // 2. HKDF để tạo khóa 32-byte (OpenSSL 3.0+ API)
    shared_key.resize(AES_KEY_SIZE);
    
    kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        cerr << "DeriveSharedSecret: Failed to fetch HKDF" << endl;
        goto cleanup;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        cerr << "DeriveSharedSecret: Failed to create HKDF context" << endl;
        goto cleanup;
    }

    // Thiết lập parameters cho HKDF (OpenSSL 3.0+ style)
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, 
                                                  (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, 
                                                   (void*)raw_secret.data(), 
                                                   raw_secret_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, 
                                                   (void*)info, 
                                                   strlen(info));
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, 
                                                   (void*)salt, 
                                                   strlen(salt));
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, shared_key.data(), AES_KEY_SIZE, params) <= 0) {
        cerr << "DeriveSharedSecret: HKDF derivation failed" << endl;
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    success = true;

cleanup:
    if (kctx) EVP_KDF_CTX_free(kctx);
    if (kdf) EVP_KDF_free(kdf);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (priv_key) EVP_PKEY_free(priv_key);
    if (peer_pub_key) EVP_PKEY_free(peer_pub_key);
    
    return success;
}

bool CryptoEngine::GenerateIV(std::vector<uint8_t>& iv) {
    iv.resize(AES_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_IV_SIZE) != 1) {
        cerr << "CryptoEngine: RAND_bytes failed" << endl;
        return false;
    }
    return true;
}

bool CryptoEngine::Encrypt(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& plaintext,
                           std::vector<uint8_t>& ciphertext,
                           std::vector<uint8_t>& tag) {
    
    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE) {
        cerr << "CryptoEngine: Invalid key or IV size for encryption" << endl;
        return false;
    }

    ciphertext.resize(plaintext.size());
    tag.resize(GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) 
        goto err_encrypt;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) 
        goto err_encrypt;
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) 
        goto err_encrypt;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) 
        goto err_encrypt;
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) 
        goto err_encrypt;
    ciphertext_len += len;
    
    ciphertext.resize(ciphertext_len);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1) 
        goto err_encrypt;

    EVP_CIPHER_CTX_free(ctx);
    return true;

err_encrypt:
    cerr << "CryptoEngine: Encryption failed" << endl;
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool CryptoEngine::Decrypt(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& tag,
                           std::vector<uint8_t>& plaintext) {

    if (key.size() != AES_KEY_SIZE || iv.size() != AES_IV_SIZE || tag.size() != GCM_TAG_SIZE) {
        cerr << "CryptoEngine: Invalid key, IV, or tag size for decryption" << endl;
        return false;
    }

    plaintext.resize(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int plaintext_len = 0;
    int ret = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) 
        goto err_decrypt;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) 
        goto err_decrypt;
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) 
        goto err_decrypt;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) 
        goto err_decrypt;
    plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag.data()) != 1) 
        goto err_decrypt;

    ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true;
    } else {
        cerr << "CryptoEngine: Decryption failed (Tag mismatch - packet discarded)" << endl;
        plaintext.clear();
        return false;
    }

err_decrypt:
    cerr << "CryptoEngine: Decryption failed" << endl;
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return false;
}