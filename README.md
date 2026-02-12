![VillageSQL Logo](https://villagesql.com/assets/logo-light.svg)

# VillageSQL Cryptographic Functions Extension

A comprehensive cryptographic extension for VillageSQL Server providing secure hashing, encryption, and password management functions. This extension complements MySQL's built-in cryptographic functions with PostgreSQL pgcrypto-compatible functionality using OpenSSL.

## Features

- **PostgreSQL Compatibility**: Implements pgcrypto-compatible functions for easy migration
- **General Hashing**: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 with `digest()` and `hmac()` functions
- **AES Encryption**: Full AES support with 128/192/256-bit keys and automatic IV management
- **Password Security**: PBKDF2-based password hashing with configurable iterations (SHA-256/SHA-512)
- **Cryptographic RNG**: Secure random byte generation and UUID v4 generation using OpenSSL
- **High Performance**: Optimized C++ implementation with OpenSSL backend

## Installation

### Option 1: Install Pre-built VEB Package
1. Download the `vsql_crypto.veb` package from releases
2. Install the VEB package to your VillageSQL instance

### Option 2: Build from Source

#### Prerequisites
- VillageSQL build directory (specified via `VillageSQL_BUILD_DIR`)
- CMake 3.16 or higher
- C++17 compatible compiler
- OpenSSL development libraries

📚 **Full Documentation**: Visit [villagesql.com/docs](https://villagesql.com/docs) for comprehensive guides on building extensions, architecture details, and more.

#### Build Instructions

1. Clone the repository (if not already done):
   ```bash
   git clone https://github.com/villagesql/vsql-crypto.git
   cd vsql-crypto
   ```

2. Configure CMake with required paths:

   **Linux:**
   ```bash
   mkdir build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=$HOME/build/villagesql
   ```

   **macOS:**
   ```bash
   mkdir build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=~/build/villagesql
   ```

   **Note**:
   - `VillageSQL_BUILD_DIR`: Path to VillageSQL build directory (contains the staged SDK and `veb_output_directory`)

3. Build the extension:
   ```bash
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2))
   ```

   This creates the `vsql_crypto.veb` package in the build directory.

4. Install the VEB (optional):
   ```bash
   make install
   ```

   This copies the VEB to the directory specified by `VEB_INSTALL_DIR`. If not using `make install`, you can manually copy the VEB file to your desired location.

The VEB (VillageSQL Extension Bundle) contains:
- `manifest.json` - Extension metadata
- `lib/vsql_crypto.so` - Compiled shared library with cryptographic functions

The extension uses the VillageSQL Extension Framework (VEF) API where functions are registered declaratively in code rather than through SQL scripts.

## Usage

After building the VEB package, install and use the extension in VillageSQL:

```sql
-- Install the extension
INSTALL EXTENSION vsql_crypto;

-- Verify the extension is loaded
SELECT crypto_version();
-- Returns: OpenSSL 3.x.x (or similar)
```

### Available Functions

#### Utility Functions

**crypto_version()** - Check OpenSSL availability and version

```sql
SELECT crypto_version();
-- Returns: OpenSSL version string (e.g., "OpenSSL 3.0.2 15 Mar 2022")
```

#### General Hashing Functions

**digest(data, type)** - Compute cryptographic hash of data

```sql
-- Supported algorithms: md5, sha1, sha224, sha256, sha384, sha512
SELECT HEX(digest('test data', 'sha256'));
SELECT HEX(digest('hello world', 'sha512'));
```

**hmac(data, key, type)** - Compute HMAC (Hash-based Message Authentication Code)

```sql
SELECT HEX(hmac('message', 'secret_key', 'sha256'));
SELECT HEX(hmac('data', 'password', 'sha1'));
```

#### Encryption Functions

**encrypt(data, key, type)** - Encrypt data using various ciphers

```sql
-- Supported ciphers: aes (aes-128, aes-192, aes-256)
SET @encrypted = encrypt('sensitive data', 'my-secret-key', 'aes-256');
SET @encrypted = encrypt('text', 'sixteen-byte-key', 'aes');
```

**decrypt(data, key, type)** - Decrypt encrypted data

```sql
SET @plaintext = 'Hello, World!';
SET @key = 'my-16-byte-key!!';
SET @encrypted = encrypt(@plaintext, @key, 'aes');
SELECT decrypt(@encrypted, @key, 'aes');
-- Returns: Hello, World!
```

#### Random Data Generation

**gen_random_bytes(count)** - Generate cryptographically secure random bytes

```sql
SELECT HEX(gen_random_bytes(16));  -- 16 random bytes as hex
SELECT HEX(gen_random_bytes(32));  -- 32 random bytes as hex
```

**gen_random_uuid()** - Generate a random UUID (version 4)

```sql
SELECT gen_random_uuid();
-- Returns: e.g., 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
```

#### Password Hashing Functions

**gen_salt(type, iter_count)** - Generate salt for password hashing

```sql
-- Generate salt for PBKDF2-SHA256
SET @salt = gen_salt('pbkdf2-sha256', 100000);
SET @salt512 = gen_salt('pbkdf2-sha512', 50000);

-- Short type aliases are also supported
SET @salt = gen_salt('sha256', 10000);  -- Same as pbkdf2-sha256
SET @salt = gen_salt('sha512', 10000);  -- Same as pbkdf2-sha512
```

Supported algorithms:
- `pbkdf2-sha256`, `sha256` - PBKDF2 with SHA-256 (recommended)
- `pbkdf2-sha512`, `sha512` - PBKDF2 with SHA-512

Recommended iteration count: 100,000 or higher (per OWASP guidelines)

**crypt(password, salt)** - Hash password using PBKDF2

```sql
-- Hash a password
SET @salt = gen_salt('pbkdf2-sha256', 10000);
SET @hash = crypt('mypassword', @salt);

-- Verify a password by comparing hashes
SET @stored_hash = crypt('mypassword', @salt);
SELECT @hash = @stored_hash;  -- Returns 1 if password matches
```

The `crypt()` function returns a formatted hash string that includes the algorithm, iteration count, salt, and hash:
```
$pbkdf2-sha256$100000$<base64-salt>$<base64-hash>
```

## Testing

The extension includes comprehensive test files using the MySQL Test Runner (MTR) framework:

- **crypto_basic.test** - Tests all functions with valid inputs (happy path)
- **crypto_errors.test** - Tests error handling for invalid inputs, NULL values, and edge cases

### Running Tests

**Option 1 (Default): Using installed VEB**

This method assumes the VEB is already installed to your VillageSQL veb_dir.

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test

# Run individual test
perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test crypto_basic
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test

# Run individual test
perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test crypto_basic
```

**Option 2: Using a specific VEB file**

Use this to test a specific VEB build without installing it first:

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test
```

### Creating or Updating Test Results

To create or update expected test results:

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test --record
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test --record
```

**Note on Error Handling**: Functions return NULL for invalid inputs (e.g., unsupported algorithms, NULL arguments) rather than throwing SQL errors. The error tests verify this behavior.

## Notes on MySQL Built-in Functions

MySQL already provides some cryptographic functions natively. This extension complements them:

**MySQL Built-in Functions (already available):**
- `MD5()`, `SHA1()`, `SHA()`, `SHA2()` - Basic hashing (returns hex string)
- `AES_ENCRYPT()`, `AES_DECRYPT()` - AES encryption
- `RANDOM_BYTES()` - Random byte generation

**This Extension Adds:**
- `digest()` - Returns binary hash (use with HEX() for hex string)
- `hmac()` - HMAC authentication codes
- `encrypt()`/`decrypt()` - Multi-cipher support with automatic IV handling
- `gen_salt()`/`crypt()` - Password hashing with PBKDF2
- `gen_random_uuid()` - UUID v4 generation
- Support for additional AES key sizes (128/192/256-bit)

## Security Considerations

- **Key Management**: Store encryption keys securely, never in your database or code
- **Algorithm Selection**: Use SHA-256 or stronger for hashing; avoid MD5 and SHA-1 for security-critical applications
- **Encryption**: AES-256 is recommended for sensitive data encryption
- **Password Hashing**: Use PBKDF2-SHA256 or PBKDF2-SHA512 for password hashing. OWASP recommends 100,000 or more iterations. Never store passwords in plain text.
- **Random Data**: `gen_random_bytes()` and `gen_random_uuid()` use OpenSSL's RAND_bytes() which is cryptographically secure

## Development

### Project Structure
```
vsql-crypto/
├── src/
│   └── crypto.cc            # VDF implementations and extension registration
├── cmake/
│   └── FindVillageSQL.cmake # CMake module to locate VillageSQL SDK
├── test/                    # MTR test suite
│   ├── t/                   # Test files (.test)
│   └── r/                   # Expected results (.result)
├── manifest.json            # VEB package manifest
└── CMakeLists.txt           # Build configuration
```

### Build Targets
- `make` - Build the extension and create the `vsql_crypto.veb` package
- `make install` - Install the VEB to the directory specified by `VEB_INSTALL_DIR`

### Implementation Details

This extension uses the VillageSQL Extension Framework (VEF) API and OpenSSL for all cryptographic operations:

- **VEF API**: Functions are registered declaratively using the builder pattern with `VEF_GENERATE_ENTRY_POINTS`
- **OpenSSL EVP API**: For hashing and encryption
- **OpenSSL HMAC API**: For message authentication codes
- **OpenSSL PKCS5_PBKDF2_HMAC**: For password hashing
- **OpenSSL RAND API**: For secure random number generation

The encryption functions automatically:
- Generate random IVs (Initialization Vectors) for each encryption
- Prepend the IV to the encrypted data
- Extract and use the IV when decrypting

## Reporting Bugs and Requesting Features

If you encounter a bug or have a feature request, please open an [issue](./issues) using GitHub Issues. Please provide as much detail as possible, including:

* A clear and descriptive title
* A detailed description of the issue or feature request
* Steps to reproduce the bug (if applicable)
* Your environment details (OS, VillageSQL version, etc.)

## License

License information can be found in the [LICENSE](./LICENSE) file.

## Contributing

VillageSQL welcomes contributions from the community. Please ensure all tests pass before submitting pull requests:

1. Build the extension:

   **Linux:**
   ```bash
   mkdir build && cd build
   cmake .. -DVillageSQL_BUILD_DIR=$HOME/build/villagesql
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2))
   ```

   **macOS:**
   ```bash
   mkdir build && cd build
   cmake .. -DVillageSQL_BUILD_DIR=~/build/villagesql
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2))
   ```

2. Run the test suite:

   **Linux:**
   ```bash
   cd $HOME/build/villagesql/mysql-test
   VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
     perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test
   ```

   **macOS:**
   ```bash
   cd ~/build/villagesql/mysql-test
   VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
     perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test
   ```

3. Submit your pull request with a clear description of changes

## Contact

We are excited you want to be part of the Village that makes VillageSQL happen. You can interact with us and the community in several ways:

* File a [bug or issue](./issues) and we will review
* Start a discussion in the project [discussions](./discussions)
* Join the [Discord channel](https://discord.gg/KSr6whd3Fr)
