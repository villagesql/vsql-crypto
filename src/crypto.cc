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

#include <villagesql/vsql.h>

#include <cstring>
#include <string>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

using namespace vsql;

// =============================================================================
// Helper Functions
// =============================================================================

// Get OpenSSL digest algorithm by name
static const EVP_MD *get_digest_algorithm(std::string_view algo_sv) {
  std::string alg(algo_sv);
  std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

  if (alg == "md5")
    return EVP_md5();
  if (alg == "sha1")
    return EVP_sha1();
  if (alg == "sha224")
    return EVP_sha224();
  if (alg == "sha256")
    return EVP_sha256();
  if (alg == "sha384")
    return EVP_sha384();
  if (alg == "sha512")
    return EVP_sha512();

  return nullptr;
}

// Cipher lookup for encrypt()/decrypt(). Exact names only: a lookalike such
// as "aes-999" must return nullptr rather than silently select a key size.
static const EVP_CIPHER *get_cipher_algorithm(const std::string &alg) {
  if (alg == "aes" || alg == "aes-128")
    return EVP_aes_128_cbc();
  if (alg == "aes-192")
    return EVP_aes_192_cbc();
  if (alg == "aes-256")
    return EVP_aes_256_cbc();

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
void crypto_version_impl(StringResult result) {
  const char *version_str = OpenSSL_version(OPENSSL_VERSION);
  result.set(version_str);
}

// digest(data, type) - Compute hash of data
void digest_impl(StringArg data_arg, StringArg type_arg, StringResult result) {
  if (data_arg.is_null() || type_arg.is_null()) {
    result.set_null();
    return;
  }

  const EVP_MD *md = get_digest_algorithm(type_arg.value());
  if (!md) {
    result.set_null();
    return;
  }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    result.set_null();
    return;
  }

  auto data_sv = data_arg.value();
  auto buf = result.buffer();

  unsigned int digest_len;
  if (EVP_DigestInit_ex(md_ctx, md, nullptr) != 1 ||
      EVP_DigestUpdate(md_ctx, data_sv.data(), data_sv.size()) != 1 ||
      EVP_DigestFinal_ex(md_ctx, reinterpret_cast<unsigned char *>(buf.data()),
                         &digest_len) != 1) {
    EVP_MD_CTX_free(md_ctx);
    result.set_null();
    return;
  }

  EVP_MD_CTX_free(md_ctx);
  result.set_length(digest_len);
}

// hmac(data, key, type) - Compute HMAC
void hmac_impl(StringArg data_arg, StringArg key_arg, StringArg type_arg,
               StringResult result) {
  if (data_arg.is_null() || key_arg.is_null() || type_arg.is_null()) {
    result.set_null();
    return;
  }

  const EVP_MD *md = get_digest_algorithm(type_arg.value());
  if (!md) {
    result.set_null();
    return;
  }

  auto data_sv = data_arg.value();
  auto key_sv = key_arg.value();
  auto buf = result.buffer();

  unsigned int hmac_len;
  if (!HMAC(md, key_sv.data(), key_sv.size(),
            reinterpret_cast<const unsigned char *>(data_sv.data()),
            data_sv.size(), reinterpret_cast<unsigned char *>(buf.data()),
            &hmac_len)) {
    result.set_null();
    return;
  }

  result.set_length(hmac_len);
}

// gen_random_bytes(count) - Generate random bytes
void gen_random_bytes_impl(IntArg count_arg, StringResult result) {
  if (count_arg.is_null()) {
    result.set_null();
    return;
  }

  long long count = count_arg.value();

  if (count <= 0 || count > 1024) {
    result.set_null();
    return;
  }

  auto buf = result.buffer();
  if (RAND_bytes(reinterpret_cast<unsigned char *>(buf.data()),
                 static_cast<int>(count)) != 1) {
    result.set_null();
    return;
  }

  result.set_length(static_cast<size_t>(count));
}

// gen_random_uuid() - Generate random UUID (version 4)
void gen_random_uuid_impl(StringResult result) {
  unsigned char uuid_bytes[16];

  if (RAND_bytes(uuid_bytes, 16) != 1) {
    result.warning("Failed to generate random bytes");
    return;
  }

  // Set version (4) and variant bits
  uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40; // Version 4
  uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80; // Variant 10

  // Format as UUID string manually
  static const char hex_chars[] = "0123456789abcdef";
  auto buf = result.buffer();
  size_t pos = 0;

  for (size_t i = 0; i < 16; ++i) {
    unsigned char byte = uuid_bytes[i];
    buf[pos++] = hex_chars[byte >> 4];
    buf[pos++] = hex_chars[byte & 0x0F];

    // Add hyphens at positions after bytes 3, 5, 7, 9
    if (i == 3 || i == 5 || i == 7 || i == 9) {
      buf[pos++] = '-';
    }
  }

  result.set_length(36);
}

// encrypt(data, key, type) - Encrypt data with various ciphers
void encrypt_impl(StringArg data_arg, StringArg key_arg, StringArg type_arg,
                  StringResult result) {
  if (data_arg.is_null() || key_arg.is_null() || type_arg.is_null()) {
    result.set_null();
    return;
  }

  // Parse cipher type
  std::string cipher_str(type_arg.value());
  std::transform(cipher_str.begin(), cipher_str.end(), cipher_str.begin(),
                 ::tolower);

  auto key_sv = key_arg.value();

  const EVP_CIPHER *cipher = get_cipher_algorithm(cipher_str);
  if (!cipher) {
    result.set_null();
    return;
  }

  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx) {
    result.set_null();
    return;
  }

  if (static_cast<int>(key_sv.size()) < EVP_CIPHER_key_length(cipher)) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    char msg[128];
    snprintf(msg, sizeof(msg), "key too short for %s: need %d bytes, got %zu",
             cipher_str.c_str(), EVP_CIPHER_key_length(cipher), key_sv.size());
    result.error(msg);
    return;
  }

  // Generate random IV
  unsigned char iv[EVP_MAX_IV_LENGTH];
  int iv_len = EVP_CIPHER_iv_length(cipher);
  if (RAND_bytes(iv, iv_len) != 1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  auto buf = result.buffer();
  auto *out_ptr = reinterpret_cast<unsigned char *>(buf.data());

  // Guard the fixed result buffer against overflow. CBC output is
  // IV + ciphertext, and ciphertext can reach data_len + one padding
  // block; writing past buf would corrupt the heap, so reject oversized
  // input with a warning (NULL) rather than overrun.
  {
    size_t need = static_cast<size_t>(iv_len) + data_arg.value().size() +
                  static_cast<size_t>(EVP_CIPHER_block_size(cipher));
    if (need > buf.size()) {
      EVP_CIPHER_CTX_free(cipher_ctx);
      result.warning("encrypt: input too large for result buffer");
      return;
    }
  }

  // Copy IV to output buffer
  memcpy(out_ptr, iv, iv_len);

  auto data_sv = data_arg.value();
  int out_len = 0, final_len = 0;

  // Initialize encryption
  if (EVP_EncryptInit_ex(cipher_ctx, cipher, nullptr,
                         reinterpret_cast<const unsigned char *>(key_sv.data()),
                         iv) != 1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  // Encrypt data
  if (EVP_EncryptUpdate(cipher_ctx, out_ptr + iv_len, &out_len,
                        reinterpret_cast<const unsigned char *>(data_sv.data()),
                        static_cast<int>(data_sv.size())) != 1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  // Finalize encryption
  if (EVP_EncryptFinal_ex(cipher_ctx, out_ptr + iv_len + out_len, &final_len) !=
      1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  EVP_CIPHER_CTX_free(cipher_ctx);
  result.set_length(static_cast<size_t>(iv_len + out_len + final_len));
}

// decrypt(data, key, type) - Decrypt data
void decrypt_impl(StringArg data_arg, StringArg key_arg, StringArg type_arg,
                  StringResult result) {
  if (data_arg.is_null() || key_arg.is_null() || type_arg.is_null()) {
    result.set_null();
    return;
  }

  // Parse cipher type
  std::string cipher_str(type_arg.value());
  std::transform(cipher_str.begin(), cipher_str.end(), cipher_str.begin(),
                 ::tolower);

  auto key_sv = key_arg.value();

  const EVP_CIPHER *cipher = get_cipher_algorithm(cipher_str);
  if (!cipher) {
    result.set_null();
    return;
  }

  int iv_len = EVP_CIPHER_iv_length(cipher);
  auto data_sv = data_arg.value();
  if (data_sv.size() < static_cast<size_t>(iv_len)) {
    result.set_null();
    return;
  }

  // Extract IV from beginning of data
  const auto *raw_data =
      reinterpret_cast<const unsigned char *>(data_sv.data());
  const unsigned char *iv = raw_data;
  const unsigned char *encrypted_data = raw_data + iv_len;
  size_t encrypted_len = data_sv.size() - iv_len;

  EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx) {
    result.set_null();
    return;
  }

  if (static_cast<int>(key_sv.size()) < EVP_CIPHER_key_length(cipher)) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    char msg[128];
    snprintf(msg, sizeof(msg), "key too short for %s: need %d bytes, got %zu",
             cipher_str.c_str(), EVP_CIPHER_key_length(cipher), key_sv.size());
    result.error(msg);
    return;
  }

  auto buf = result.buffer();
  auto *out_ptr = reinterpret_cast<unsigned char *>(buf.data());
  int out_len = 0, final_len = 0;

  // Guard the fixed result buffer against overflow (see encrypt_impl):
  // plaintext output can reach encrypted_len + one cipher block.
  {
    size_t need =
        encrypted_len + static_cast<size_t>(EVP_CIPHER_block_size(cipher));
    if (need > buf.size()) {
      EVP_CIPHER_CTX_free(cipher_ctx);
      result.warning("decrypt: input too large for result buffer");
      return;
    }
  }

  // Initialize decryption
  if (EVP_DecryptInit_ex(cipher_ctx, cipher, nullptr,
                         reinterpret_cast<const unsigned char *>(key_sv.data()),
                         iv) != 1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  // Decrypt data
  if (EVP_DecryptUpdate(cipher_ctx, out_ptr, &out_len, encrypted_data,
                        static_cast<int>(encrypted_len)) != 1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  // Finalize decryption
  if (EVP_DecryptFinal_ex(cipher_ctx, out_ptr + out_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(cipher_ctx);
    result.set_null();
    return;
  }

  EVP_CIPHER_CTX_free(cipher_ctx);
  result.set_length(static_cast<size_t>(out_len + final_len));
}

// gen_salt(type, iter_count) - Generate salt for password hashing
void gen_salt_impl(StringArg type_arg, IntArg iter_arg, StringResult result) {
  if (type_arg.is_null()) {
    result.set_null();
    return;
  }

  std::string type(type_arg.value());
  std::transform(type.begin(), type.end(), type.begin(), ::tolower);

  // Default iteration count
  int iter_count = 100000;
  if (!iter_arg.is_null()) {
    long long val = iter_arg.value();
    if (val < 1 || val > 10000000) {
      result.set_null();
      return;
    }
    iter_count = static_cast<int>(val);
  }

  // Generate 16 random bytes for salt
  unsigned char salt_bytes[16];
  if (RAND_bytes(salt_bytes, 16) != 1) {
    result.set_null();
    return;
  }

  std::string salt_b64 = base64_encode(salt_bytes, 16);
  std::string output;

  if (type == "pbkdf2-sha256" || type == "pbkdf2" || type == "sha256") {
    output = "$pbkdf2-sha256$" + std::to_string(iter_count) + "$" + salt_b64;
  } else if (type == "pbkdf2-sha512" || type == "sha512") {
    output = "$pbkdf2-sha512$" + std::to_string(iter_count) + "$" + salt_b64;
  } else {
    result.set_null();
    return;
  }

  result.set(output);
}

// crypt(password, salt) - Hash password using PBKDF2
void crypt_impl(StringArg password_arg, StringArg salt_arg,
                StringResult result) {
  if (password_arg.is_null() || salt_arg.is_null()) {
    result.set_null();
    return;
  }

  std::string password(password_arg.value());
  std::string salt_str(salt_arg.value());

  // Parse salt string format: $algorithm$rounds$salt or
  // $algorithm$rounds$salt$hash
  if (salt_str.empty() || salt_str[0] != '$') {
    result.set_null();
    return;
  }

  // Find the parts
  size_t pos1 = salt_str.find('$', 1);
  if (pos1 == std::string::npos) {
    result.set_null();
    return;
  }
  size_t pos2 = salt_str.find('$', pos1 + 1);
  if (pos2 == std::string::npos) {
    result.set_null();
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
    result.set_null();
    return;
  }

  // Decode salt
  unsigned char salt_bytes[256];
  int salt_len = base64_decode(salt_b64, salt_bytes, sizeof(salt_bytes));
  if (salt_len < 0) {
    result.set_null();
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
    result.set_null();
    return;
  }

  // Compute PBKDF2
  unsigned char hash[64];
  if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                        salt_bytes, salt_len, rounds, md, hash_len,
                        hash) != 1) {
    result.set_null();
    return;
  }

  // Encode hash
  std::string hash_b64 = base64_encode(hash, hash_len);

  // Build output
  std::string output = "$" + algorithm + "$" + std::to_string(rounds) + "$" +
                       salt_b64 + "$" + hash_b64;

  result.set(output);
}

// =============================================================================
// Extension Registration
// =============================================================================

VEF_GENERATE_ENTRY_POINTS(
    make_extension()
        // Utility functions
        .func(make_func<&crypto_version_impl>("crypto_version")
                  .returns(STRING)
                  .no_params()
                  .buffer_size(256)
                  .deterministic()
                  .build())

        // Hash functions
        .func(make_func<&digest_impl>("digest")
                  .returns(STRING)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(64)
                  .deterministic()
                  .build())

        .func(make_func<&hmac_impl>("hmac")
                  .returns(STRING)
                  .param(STRING)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(64)
                  .deterministic()
                  .build())

        // Random data generation
        .func(make_func<&gen_random_bytes_impl>("gen_random_bytes")
                  .returns(STRING)
                  .param(INT)
                  .buffer_size(1024)
                  .build())

        .func(make_func<&gen_random_uuid_impl>("gen_random_uuid")
                  .returns(STRING)
                  .no_params()
                  .buffer_size(37)
                  .build())

        // Encryption/Decryption
        .func(make_func<&encrypt_impl>("encrypt")
                  .returns(STRING)
                  .param(STRING)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(65535)
                  .build())

        .func(make_func<&decrypt_impl>("decrypt")
                  .returns(STRING)
                  .param(STRING)
                  .param(STRING)
                  .param(STRING)
                  .buffer_size(65535)
                  .deterministic()
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
                  .deterministic()
                  .build()))
