# AGENTS.md

This file provides guidance to AI coding assistants when working with code in this repository.

**Note**: Also check `AGENTS.local.md` for additional local development instructions when present.

## Project Overview

This is a VillageSQL extension that provides cryptographic functions for hashing, encryption, and random data generation. The extension uses OpenSSL and implements functionality similar to PostgreSQL's pgcrypto module, complementing MySQL's built-in cryptographic functions.

## Build System

**IMPORTANT**: Always build in the `build/` directory, never in the source root. Building in the source root creates files that should not be checked into git.

### Build Instructions

1. Configure CMake with required paths:
   ```bash
   mkdir build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=/path/to/villagesql/build
   ```

   **Note**:
   - `VillageSQL_BUILD_DIR`: Path to VillageSQL build directory (contains the staged SDK and `veb_output_directory`)

2. Build the extension:
   ```bash
   make
   ```

3. Install the VEB (optional):
   ```bash
   make install
   ```

The build process:
1. Uses CMake with the VillageSQL Extension Framework SDK
2. Compiles C++ source files into shared library `vsql_crypto.so`
3. Packages library with `manifest.json` into `vsql_crypto.veb` package using `VEF_CREATE_VEB()` macro
4. VEB can be installed to VillageSQL for use
5. OpenSSL libraries are linked during build

See `AGENTS.local.md` for machine-specific build paths and configurations.

## Architecture

**Core Components:**
- `src/crypto.cc` - VEF implementations for cryptographic functions
- `manifest.json` - Extension metadata (name, version, description, author, license)
- `CMakeLists.txt` - CMake build configuration
- `cmake/FindVillageSQL.cmake` - CMake module to locate VillageSQL SDK
- `test/t/` - Test files directory (`.test` files using MTR framework)
- `test/r/` - Expected test results directory (`.result` files)

**Available Functions:**

All functions are accessed using the `vsql_crypto.` namespace prefix:

- `vsql_crypto.crypto_version()` - Return OpenSSL version information
- `vsql_crypto.digest(data, type)` - Compute cryptographic hash (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
- `vsql_crypto.hmac(data, key, type)` - Compute HMAC (Hash-based Message Authentication Code)
- `vsql_crypto.encrypt(data, key, type)` - Encrypt data with AES (128/192/256-bit)
- `vsql_crypto.decrypt(data, key, type)` - Decrypt encrypted data
- `vsql_crypto.gen_salt(type, iter_count)` - Generate salt for password hashing using PBKDF2 (SHA-256/SHA-512)
- `vsql_crypto.crypt(password, salt)` - Hash password using PBKDF2 with configurable iterations
- `vsql_crypto.gen_random_bytes(count)` - Generate cryptographically secure random bytes
- `vsql_crypto.gen_random_uuid()` - Generate random UUID v4

**Error Handling:**
- Functions return NULL for invalid inputs (unsupported algorithms, NULL arguments, corrupted data)
- Functions set result->type to IS_NULL for errors
- This behavior is validated in the `crypto_errors.test` test suite

**Dependencies:**
- VillageSQL Extension Framework SDK
- C++ compiler with C++17 support
- OpenSSL (linked during build)

**Code Organization:**
- File naming: lowercase with underscores (e.g., `crypto.cc`)
- Function naming: lowercase with underscores (e.g., `gen_random_uuid`)
- Variable naming: lowercase with underscores (e.g., `digest_len`)
- All cryptographic operations use OpenSSL APIs (EVP, HMAC, RAND)

## VillageSQL Extension Framework (VEF) API Pattern

Functions use the VillageSQL Extension Framework API with the following pattern:

### Function Implementation Pattern

```cpp
void my_function_impl(vef_context_t* ctx,
                      vef_invalue_t* arg1, vef_invalue_t* arg2,
                      vef_vdf_result_t* result) {
    // Check for NULL arguments
    if (arg1->is_null || arg2->is_null) {
        result->type = IS_NULL;
        return;
    }

    // Access argument values
    const char* str_value = arg1->str_value;
    size_t str_len = arg1->str_len;
    const unsigned char* bin_value = arg1->bin_value;
    size_t bin_len = arg1->bin_len;
    long long int_value = arg1->int_value;

    // Perform function logic
    // ...

    // Set result
    result->type = IS_VALUE;  // or IS_NULL or IS_ERROR
    result->actual_len = result_length;
    // Write to result->str_buf or result->bin_buf
}
```

### Function Registration Pattern

```cpp
#include <villagesql/extension.h>

using namespace villagesql::extension_builder;
using namespace villagesql::func_builder;
using namespace villagesql::type_builder;

VEF_GENERATE_ENTRY_POINTS(
  make_extension("extension_name", "1.0.0")
    .func(make_func<&my_function_impl>("my_function")
      .returns(STRING)  // or INT, etc.
      .param(STRING)    // add .param() for each parameter
      .param(INT)
      .buffer_size(1024)  // max result size
      .build())
)
```

### Key Differences from Old MySQL UDF API:
- No separate init/main/deinit functions - single implementation function
- Arguments passed as `vef_invalue_t*` structs with `is_null`, `str_value`, `bin_value`, `int_value` fields
- Results set via `vef_vdf_result_t*` with `type`, `str_buf`, `bin_buf`, `actual_len` fields
- Function registration done declaratively in code using builder pattern
- No install.sql needed - functions registered at extension load time

## Testing

The extension includes comprehensive test files using the MySQL Test Runner (MTR) framework:
- **Test Location**:
  - `test/t/` directory contains `.test` files with SQL test commands
  - `test/r/` directory contains `.result` files with expected output
- **Test Files**:
  - `crypto_basic.test` - Tests all functions with valid inputs (happy path)
  - `crypto_errors.test` - Tests error handling for invalid inputs, NULL values, and edge cases

### Running Tests

**Option 1 (Default): Using installed VEB**

This method assumes the VEB is already installed to your VillageSQL veb_dir:

```bash
cd /path/to/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test

# Run individual test
perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test crypto_basic
```

**Option 2: Using a specific VEB file**

Use this to test a specific VEB build without installing it first:

```bash
cd /path/to/mysql-test
VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test
```

### Creating or Updating Test Results

Use `--record` flag to generate or update expected `.result` files:

```bash
cd /path/to/mysql-test
VSQL_CRYPTO_VEB=/path/to/vsql-crypto/build/vsql_crypto.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-crypto/test --record
```

### Test Guidelines

- Tests should validate function output and behavior
- Each test should install the extension, run tests, and clean up (uninstall extension)
- **Error Handling**: Functions return NULL for errors (result->type = IS_NULL)

## Extension Installation

After building the extension, install it in VillageSQL:

```sql
INSTALL EXTENSION 'vsql_crypto';
```

Then test the functions:
```sql
SELECT HEX(digest('test', 'sha256'));
SELECT gen_random_uuid();
SELECT HEX(hmac('data', 'key', 'sha256'));
```

## Adding New Cryptographic Functions

To add new cryptographic functions to this extension:

1. **Implement the VDF in `src/crypto.cc`**:
   - Add the implementation function with signature: `void func_impl(vef_context_t*, vef_invalue_t*..., vef_vdf_result_t*)`
   - Use OpenSSL APIs for cryptographic operations
   - Check for NULL arguments and set `result->type = IS_NULL` on error
   - Set `result->type = IS_VALUE` and populate `result->str_buf` or `result->bin_buf` on success
   - Include copyright header if creating new files

2. **Register the function in the extension**:
   - Add function registration in `VEF_GENERATE_ENTRY_POINTS` block
   - Use `make_func<&func_impl>("function_name")` with appropriate `.returns()`, `.param()`, and `.buffer_size()` settings

3. **Create tests**:
   - Add happy path tests to `test/t/crypto_basic.test` or create new test files
   - Add error handling tests to `test/t/crypto_errors.test`
   - Generate expected results using `--record` flag
   - Test various inputs including edge cases, NULL values, and invalid parameters

4. **Update documentation**:
   - Add function descriptions to README.md
   - Update AGENTS.md with new function signatures

## Licensing and Copyright

All source code files (`.cc`, `.h`, `.cpp`, `.hpp`) and CMake files (`CMakeLists.txt`) must include the following copyright header at the top of the file:

```
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
```

When creating new source files, always include this copyright block before any code or includes.

## Common Tasks for AI Agents

When asked to add functionality to this extension:

1. **Adding a new function**: Create the VDF implementation in src/crypto.cc, register it in VEF_GENERATE_ENTRY_POINTS, create both happy path and error handling tests
2. **Modifying build**: Edit CMakeLists.txt, ensure proper library linking
3. **Adding dependencies**: Update CMakeLists.txt with find_package() or target_link_libraries()
4. **Testing**:
   - Create or update `.test` files in `test/t/` directory
   - Add both valid input tests (crypto_basic.test) and error handling tests (crypto_errors.test)
   - Generate expected results with `--record` flag
   - Verify all tests pass with `perl mysql-test-run.pl --suite=<path>`
5. **Documentation**: Update README.md and AGENTS.md to reflect new functionality

Always maintain consistency with existing code style and include proper copyright headers.
