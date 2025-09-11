// // base64.cpp
// #include "base64.h"
// #include <stdexcept>

// static const std::string base64_chars = 
//     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// std::string base64_encode(const uint8_t* data, size_t len) {
//     std::string ret;
//     int i = 0, j = 0;
//     uint8_t char_array_3[3], char_array_4[4];

//     while (len--) {
//         char_array_3[i++] = *(data++);
//         if (i == 3) {
//             char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
//             char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
//             char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
//             char_array_4[3] = char_array_3[2] & 0x3f;

//             for (i = 0; i < 4; i++)
//                 ret += base64_chars[char_array_4[i]];
//             i = 0;
//         }
//     }

//     if (i) {
//         for (j = i; j < 3; j++)
//             char_array_3[j] = '\0';

//         char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
//         char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
//         char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

//         for (j = 0; j < i + 1; j++)
//             ret += base64_chars[char_array_4[j]];

//         while (i++ < 3)
//             ret += '=';
//     }
//     return ret;
// }

// std::vector<uint8_t> base64_decode(const std::string& encoded) {
//     std::vector<uint8_t> ret;
//     int i = 0, j = 0;
//     int in_len = encoded.size();
//     uint8_t char_array_4[4], char_array_3[3];

//     for (int in_ = 0; in_ < in_len;) {
//         for (i = 0; i < 4 && in_ < in_len; i++, in_++) {
//             char c = encoded[in_];
//             if (c == '=') break;
//             auto pos = base64_chars.find(c);
//             if (pos == std::string::npos) throw std::runtime_error("Invalid base64 character");
//             char_array_4[i] = pos;
//         }

//         char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
//         char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
//         char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

//         for (j = 0; j < i - 1; j++)
//             ret.push_back(char_array_3[j]);
//     }

//     return ret;
// }