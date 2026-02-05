/* Copyright (c) 2025 VillageSQL Contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <villagesql/extension.h>

#include <cstring>
#include <string>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

using namespace villagesql::extension_builder;
using namespace villagesql::func_builder;
using namespace villagesql::type_builder;

// =============================================================================
// Helper Functions
// =============================================================================

// Get OpenSSL digest algorithm by name
static const EVP_MD* get_digest_algorithm(const char* algo, size_t algo_len) {
    std::string alg(algo, algo_len);
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    if (alg == "md5") return EVP_md5();
    if (alg == "sha1") return EVP_sha1();
    if (alg == "sha224") return EVP_sha224();
    if (alg == "sha256") return EVP_sha256();
    if (alg == "sha384") return EVP_sha384();
    if (alg == "sha512") return EVP_sha512();

    return nullptr;
}

// Base64 encoding for password hashing
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const unsigned char* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        unsigned int val = data[i] << 16;
        if (i + 1 < len) val |= data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];

        result += base64_chars[(val >> 18) & 0x3F];
        result += base64_chars[(val >> 12) & 0x3F];
        result += (i + 1 < len) ? base64_chars[(val >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? base64_chars[val & 0x3F] : '=';
    }

    // Remove padding for crypt-style format
    while (!result.empty() && result.back() == '=') {
        result.pop_back();
    }

    return result;
}

static int base64_decode(const std::string& encoded, unsigned char* decoded, size_t max_len) {
    static int decode_table[256];
    static bool table_initialized = false;

    if (!table_initialized) {
        memset(decode_table, -1, sizeof(decode_table));
        for (int i = 0; i < 64; i++) {
            decode_table[(int)base64_chars[i]] = i;
        }
        table_initialized = true;
    }

    std::string padded = encoded;
    while (padded.length() % 4 != 0) {
        padded += '=';
    }

    int decoded_len = 0;
    for (size_t i = 0; i < padded.length(); i += 4) {
        if (decoded_len + 3 > (int)max_len) return -1;

        int val = 0;
        for (int j = 0; j < 4; j++) {
            if (padded[i + j] == '=') break;
            int idx = decode_table[(int)padded[i + j]];
            if (idx < 0) return -1;
            val = (val << 6) | idx;
        }

        decoded[decoded_len++] = (val >> 16) & 0xFF;
        if (padded[i + 2] != '=') decoded[decoded_len++] = (val >> 8) & 0xFF;
        if (padded[i + 3] != '=') decoded[decoded_len++] = val & 0xFF;
    }

    return decoded_len;
}

// =============================================================================
// VDF Implementations
// =============================================================================

// crypto_version() - Returns OpenSSL version
void crypto_version_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
    const char* version_str = OpenSSL_version(OPENSSL_VERSION);
    size_t len = strlen(version_str);

    if (len >= sizeof(result->str_buf)) {
        len = sizeof(result->str_buf) - 1;
    }

    memcpy(result->str_buf, version_str, len);
    result->str_buf[len] = '\0';
    result->type = VEF_RESULT_VALUE;
    result->actual_len = len;
}

// digest(data, type) - Compute hash of data
void digest_impl(vef_context_t* ctx,
                 vef_invalue_t* data_arg, vef_invalue_t* type_arg,
                 vef_vdf_result_t* result) {
    if (data_arg->is_null || type_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    const EVP_MD* md = get_digest_algorithm(type_arg->str_value, type_arg->str_len);
    if (!md) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    unsigned int digest_len;
    if (EVP_DigestInit_ex(md_ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(md_ctx, data_arg->bin_value, data_arg->bin_len) != 1 ||
        EVP_DigestFinal_ex(md_ctx, result->bin_buf, &digest_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    EVP_MD_CTX_free(md_ctx);
    result->type = VEF_RESULT_VALUE;
    result->actual_len = digest_len;
}

// hmac(data, key, type) - Compute HMAC
void hmac_impl(vef_context_t* ctx,
               vef_invalue_t* data_arg, vef_invalue_t* key_arg, vef_invalue_t* type_arg,
               vef_vdf_result_t* result) {
    if (data_arg->is_null || key_arg->is_null || type_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    const EVP_MD* md = get_digest_algorithm(type_arg->str_value, type_arg->str_len);
    if (!md) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    unsigned int hmac_len;
    if (!HMAC(md, key_arg->bin_value, key_arg->bin_len,
              data_arg->bin_value, data_arg->bin_len,
              result->bin_buf, &hmac_len)) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    result->type = VEF_RESULT_VALUE;
    result->actual_len = hmac_len;
}

// gen_random_bytes(count) - Generate random bytes
void gen_random_bytes_impl(vef_context_t* ctx,
                           vef_invalue_t* count_arg,
                           vef_vdf_result_t* result) {
    if (count_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    long long count = count_arg->int_value;

    if (count <= 0 || count > 1024) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    if (RAND_bytes(result->bin_buf, count) != 1) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    result->type = VEF_RESULT_VALUE;
    result->actual_len = count;
}

// gen_random_uuid() - Generate random UUID (version 4)
void gen_random_uuid_impl(vef_context_t* ctx, vef_vdf_result_t* result) {
    unsigned char uuid_bytes[16];

    if (RAND_bytes(uuid_bytes, 16) != 1) {
        result->type = VEF_RESULT_ERROR;
        strcpy(result->error_msg, "Failed to generate random bytes");
        return;
    }

    // Set version (4) and variant bits
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;  // Version 4
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;  // Variant 10

    // Format as UUID string manually
    static const char hex_chars[] = "0123456789abcdef";
    size_t pos = 0;

    for (size_t i = 0; i < 16; ++i) {
        unsigned char byte = uuid_bytes[i];
        result->str_buf[pos++] = hex_chars[byte >> 4];
        result->str_buf[pos++] = hex_chars[byte & 0x0F];

        // Add hyphens at positions after bytes 3, 5, 7, 9
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            result->str_buf[pos++] = '-';
        }
    }

    result->type = VEF_RESULT_VALUE;
    result->actual_len = 36;
}

// encrypt(data, key, type) - Encrypt data with various ciphers
void encrypt_impl(vef_context_t* ctx,
                  vef_invalue_t* data_arg, vef_invalue_t* key_arg, vef_invalue_t* type_arg,
                  vef_vdf_result_t* result) {
    if (data_arg->is_null || key_arg->is_null || type_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Parse cipher type
    std::string cipher_str(type_arg->str_value, type_arg->str_len);
    std::transform(cipher_str.begin(), cipher_str.end(), cipher_str.begin(), ::tolower);

    const EVP_CIPHER* cipher = nullptr;
    if (cipher_str.find("aes") != std::string::npos) {
        if (cipher_str.find("128") != std::string::npos || key_arg->bin_len == 16) {
            cipher = EVP_aes_128_cbc();
        } else if (cipher_str.find("192") != std::string::npos || key_arg->bin_len == 24) {
            cipher = EVP_aes_192_cbc();
        } else if (cipher_str.find("256") != std::string::npos || key_arg->bin_len == 32) {
            cipher = EVP_aes_256_cbc();
        } else {
            cipher = EVP_aes_128_cbc();  // Default
        }
    } else {
        result->type = VEF_RESULT_NULL;
        return;
    }

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Generate random IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = EVP_CIPHER_iv_length(cipher);
    if (RAND_bytes(iv, iv_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Copy IV to output buffer
    memcpy(result->bin_buf, iv, iv_len);

    int out_len = 0, final_len = 0;

    // Initialize encryption
    if (EVP_EncryptInit_ex(cipher_ctx, cipher, nullptr, key_arg->bin_value, iv) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Encrypt data
    if (EVP_EncryptUpdate(cipher_ctx, result->bin_buf + iv_len, &out_len,
                         data_arg->bin_value, data_arg->bin_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(cipher_ctx, result->bin_buf + iv_len + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);

    result->type = VEF_RESULT_VALUE;
    result->actual_len = iv_len + out_len + final_len;
}

// decrypt(data, key, type) - Decrypt data
void decrypt_impl(vef_context_t* ctx,
                  vef_invalue_t* data_arg, vef_invalue_t* key_arg, vef_invalue_t* type_arg,
                  vef_vdf_result_t* result) {
    if (data_arg->is_null || key_arg->is_null || type_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Parse cipher type
    std::string cipher_str(type_arg->str_value, type_arg->str_len);
    std::transform(cipher_str.begin(), cipher_str.end(), cipher_str.begin(), ::tolower);

    const EVP_CIPHER* cipher = nullptr;
    if (cipher_str.find("aes") != std::string::npos) {
        if (cipher_str.find("128") != std::string::npos || key_arg->bin_len == 16) {
            cipher = EVP_aes_128_cbc();
        } else if (cipher_str.find("192") != std::string::npos || key_arg->bin_len == 24) {
            cipher = EVP_aes_192_cbc();
        } else if (cipher_str.find("256") != std::string::npos || key_arg->bin_len == 32) {
            cipher = EVP_aes_256_cbc();
        } else {
            cipher = EVP_aes_128_cbc();
        }
    } else {
        result->type = VEF_RESULT_NULL;
        return;
    }

    int iv_len = EVP_CIPHER_iv_length(cipher);
    if (data_arg->bin_len < (size_t)iv_len) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Extract IV from beginning of data
    const unsigned char* iv = data_arg->bin_value;
    const unsigned char* encrypted_data = data_arg->bin_value + iv_len;
    size_t encrypted_len = data_arg->bin_len - iv_len;

    EVP_CIPHER_CTX* cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    int out_len = 0, final_len = 0;

    // Initialize decryption
    if (EVP_DecryptInit_ex(cipher_ctx, cipher, nullptr, key_arg->bin_value, iv) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Decrypt data
    if (EVP_DecryptUpdate(cipher_ctx, result->bin_buf, &out_len,
                         encrypted_data, encrypted_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(cipher_ctx, result->bin_buf + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        result->type = VEF_RESULT_NULL;
        return;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);

    result->type = VEF_RESULT_VALUE;
    result->actual_len = out_len + final_len;
}

// gen_salt(type, iter_count) - Generate salt for password hashing
void gen_salt_impl(vef_context_t* ctx,
                   vef_invalue_t* type_arg, vef_invalue_t* iter_arg,
                   vef_vdf_result_t* result) {
    if (type_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    std::string type(type_arg->str_value, type_arg->str_len);
    std::transform(type.begin(), type.end(), type.begin(), ::tolower);

    // Default iteration count
    int iter_count = 100000;
    if (iter_arg && !iter_arg->is_null) {
        long long val = iter_arg->int_value;
        if (val < 1 || val > 10000000) {
            result->type = VEF_RESULT_NULL;
            return;
        }
        iter_count = (int)val;
    }

    // Generate 16 random bytes for salt
    unsigned char salt_bytes[16];
    if (RAND_bytes(salt_bytes, 16) != 1) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    std::string salt_b64 = base64_encode(salt_bytes, 16);
    std::string output;

    if (type == "pbkdf2-sha256" || type == "pbkdf2" || type == "sha256") {
        output = "$pbkdf2-sha256$" + std::to_string(iter_count) + "$" + salt_b64;
    } else if (type == "pbkdf2-sha512" || type == "sha512") {
        output = "$pbkdf2-sha512$" + std::to_string(iter_count) + "$" + salt_b64;
    } else {
        result->type = VEF_RESULT_NULL;
        return;
    }

    memcpy(result->str_buf, output.c_str(), output.length());
    result->str_buf[output.length()] = '\0';
    result->type = VEF_RESULT_VALUE;
    result->actual_len = output.length();
}

// crypt(password, salt) - Hash password using PBKDF2
void crypt_impl(vef_context_t* ctx,
                vef_invalue_t* password_arg, vef_invalue_t* salt_arg,
                vef_vdf_result_t* result) {
    if (password_arg->is_null || salt_arg->is_null) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    std::string password(password_arg->str_value, password_arg->str_len);
    std::string salt_str(salt_arg->str_value, salt_arg->str_len);

    // Parse salt string format: $algorithm$rounds$salt or $algorithm$rounds$salt$hash
    if (salt_str.empty() || salt_str[0] != '$') {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Find the parts
    size_t pos1 = salt_str.find('$', 1);
    if (pos1 == std::string::npos) {
        result->type = VEF_RESULT_NULL;
        return;
    }
    size_t pos2 = salt_str.find('$', pos1 + 1);
    if (pos2 == std::string::npos) {
        result->type = VEF_RESULT_NULL;
        return;
    }
    size_t pos3 = salt_str.find('$', pos2 + 1);

    std::string algorithm = salt_str.substr(1, pos1 - 1);
    std::string rounds_str = salt_str.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string salt_b64;

    if (pos3 == std::string::npos) {
        salt_b64 = salt_str.substr(pos2 + 1);
    } else {
        salt_b64 = salt_str.substr(pos2 + 1, pos3 - pos2 - 1);
    }

    int rounds = atoi(rounds_str.c_str());
    if (rounds < 1 || rounds > 10000000) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Decode salt
    unsigned char salt_bytes[256];
    int salt_len = base64_decode(salt_b64, salt_bytes, sizeof(salt_bytes));
    if (salt_len < 0) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Determine hash algorithm and output length
    const EVP_MD *md;
    int hash_len;

    if (algorithm == "pbkdf2-sha256") {
        md = EVP_sha256();
        hash_len = 32;
    } else if (algorithm == "pbkdf2-sha512") {
        md = EVP_sha512();
        hash_len = 64;
    } else {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Compute PBKDF2
    unsigned char hash[64];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt_bytes, salt_len,
                          rounds, md, hash_len, hash) != 1) {
        result->type = VEF_RESULT_NULL;
        return;
    }

    // Encode hash
    std::string hash_b64 = base64_encode(hash, hash_len);

    // Build output
    std::string output = "$" + algorithm + "$" + std::to_string(rounds) +
                        "$" + salt_b64 + "$" + hash_b64;

    memcpy(result->str_buf, output.c_str(), output.length());
    result->str_buf[output.length()] = '\0';
    result->type = VEF_RESULT_VALUE;
    result->actual_len = output.length();
}

// =============================================================================
// Extension Registration
// =============================================================================

VEF_GENERATE_ENTRY_POINTS(
  make_extension("vsql_crypto", "0.0.1")
    // Utility functions
    .func(make_func<&crypto_version_impl>("crypto_version")
      .returns(STRING)
      .buffer_size(256)
      .build())

    // Hash functions
    .func(make_func<&digest_impl>("digest")
      .returns(STRING)
      .param(STRING)
      .param(STRING)
      .buffer_size(64)
      .build())

    .func(make_func<&hmac_impl>("hmac")
      .returns(STRING)
      .param(STRING)
      .param(STRING)
      .param(STRING)
      .buffer_size(64)
      .build())

    // Random data generation
    .func(make_func<&gen_random_bytes_impl>("gen_random_bytes")
      .returns(STRING)
      .param(INT)
      .buffer_size(1024)
      .build())

    .func(make_func<&gen_random_uuid_impl>("gen_random_uuid")
      .returns(STRING)
      .buffer_size(37)
      .build())

    // Encryption/Decryption
    .func(make_func<&encrypt_impl>("encrypt")
      .returns(STRING)
      .param(STRING)
      .param(STRING)
      .param(STRING)
      .buffer_size(8192)
      .build())

    .func(make_func<&decrypt_impl>("decrypt")
      .returns(STRING)
      .param(STRING)
      .param(STRING)
      .param(STRING)
      .buffer_size(8192)
      .build())

    // Password hashing
    .func(make_func<&gen_salt_impl>("gen_salt")
      .returns(STRING)
      .param(STRING)
      .param(INT)
      .buffer_size(256)
      .build())

    .func(make_func<&crypt_impl>("crypt")
      .returns(STRING)
      .param(STRING)
      .param(STRING)
      .buffer_size(512)
      .build())
)
