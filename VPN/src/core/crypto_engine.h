#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @class CryptoEngine
 * @brief Cung cấp các hàm tĩnh (static) để thực hiện
 * trao đổi khóa (ECDH/X25519), tạo khóa (HKDF)
 * và mã hóa/giải mã (AES-256-GCM).
 *
 * Lớp này không chứa trạng thái, tất cả các hàm đều là static
 * và nhận mọi thứ cần thiết qua tham số.
 */
class CryptoEngine {
public:
    // Các hằng số kích thước
    static constexpr int AES_KEY_SIZE = 32;   // 256 bits
    static constexpr int AES_IV_SIZE = 12;    // 96 bits (GCM standard)
    static constexpr int GCM_TAG_SIZE = 16;   // 128 bits

    /**
     * @brief Tạo một cặp khóa X25519 mới (private/public).
     *
     * Sử dụng OpenSSL để tạo ra một cặp khóa bất đối xứng dựa trên
     * đường cong Elliptic Curve 25519 (X25519).
     *
     * @param private_key_pem Output: Chuỗi PEM chứa private key.
     * @param public_key_pem  Output: Chuỗi PEM chứa public key.
     * @return true nếu tạo cặp khóa thành công.
     */
    static bool GenerateKeyPair(std::string& private_key_pem, std::string& public_key_pem);
    
    /**
     * @brief Tạo ra một khóa bí mật chung (shared secret) từ private key CỦA BẠN 
     * và public key CỦA BÊN KIA.
     *
     * Hàm này thực hiện hai bước:
     * 1. ECDH: Tính toán ra "raw secret" bằng private key của bạn và public key của đối tác.
     * 2. HKDF: Dùng "raw secret" làm đầu vào cho Hàm Rút gọn Khóa (KDF)
     * để tạo ra một khóa 32-byte (256-bit) an toàn cho AES.
     *
     * @param private_key_pem Private key của bạn (định dạng PEM).
     * @param public_key_pem  Public key của bên kia (định dạng PEM).
     * @param shared_key      Output: Vector 32-byte chứa khóa AES-256 cuối cùng.
     * @return true nếu tạo khóa chung thành công.
     */
    static bool DeriveSharedSecret(const std::string& private_key_pem,
                                    const std::string& public_key_pem,
                                    std::vector<uint8_t>& shared_key);

    /**
     * @brief Tạo một IV (Initialization Vector) / Nonce ngẫu nhiên (12 bytes).
     *
     * Tạo ra một dãy 12-byte ngẫu nhiên an toàn (cryptographically secure)
     * để sử dụng làm Nonce cho mã hóa AES-GCM.
     *
     * @param iv Output: Vector 12-byte chứa IV.
     * @return true nếu tạo IV thành công.
     */
    static bool GenerateIV(std::vector<uint8_t>& iv);

    /**
     * @brief Mã hóa plaintext bằng AES-256-GCM.
     *
     * Sử dụng thuật toán mã hóa xác thực (AEAD) AES-256-GCM.
     * Nó sẽ mã hóa dữ liệu và tạo ra một thẻ (Tag) xác thực.
     *
     * @param key        Khóa 32-byte (từ DeriveSharedSecret).
     * @param iv         IV (Nonce) 12-byte. **KHÔNG ĐƯỢC DÙNG LẠI (Key, IV) NÀY**.
     * @param plaintext  Dữ liệu (gói tin IP) cần mã hóa.
     * @param ciphertext Output: Dữ liệu đã mã hóa.
     * @param tag        Output: Thẻ xác thực 16-byte (GCM Tag).
     * @return true nếu mã hóa thành công.
     */
    static bool Encrypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& tag);

    /**
     * @brief Giải mã ciphertext bằng AES-256-GCM.
     *
     * Hàm này sẽ giải mã dữ liệu VÀ kiểm tra xem `tag` có
     * khớp với dữ liệu đã giải mã hay không.
     *
     * @param key        Khóa 32-byte (phải giống hệt khóa lúc mã hóa).
     * @param iv         IV 12-byte (trích xuất từ gói tin).
     * @param ciphertext Dữ liệu mã hóa (trích xuất từ gói tin).
     * @param tag        Thẻ xác thực 16-byte (trích xuất từ gói tin).
     * @param plaintext  Output: Dữ liệu đã giải mã (gói tin IP).
     * @return true nếu GIẢI MÃ và XÁC THỰC (Tag khớp) thành công.
     * false nếu Tag không khớp (gói tin bị giả mạo/hỏng).
     */
    static bool Decrypt(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& tag,
                        std::vector<uint8_t>& plaintext);
};

#endif // CRYPTO_ENGINE_H