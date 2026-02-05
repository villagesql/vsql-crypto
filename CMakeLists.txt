cmake_minimum_required(VERSION 3.16)
project(vsql_crypto_extension)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Extension name
set(EXTENSION_NAME "vsql_crypto")

# Find VillageSQL SDK
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(VillageSQL REQUIRED)

message(STATUS "VillageSQL SDK found at: ${VillageSQL_PREFIX}")
message(STATUS "VillageSQL include dir: ${VillageSQL_INCLUDE_DIR}")

# Find OpenSSL (required for cryptographic operations)
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# Create the crypto shared library
add_library(crypto SHARED
    src/crypto.cc
)

# Include directories
target_include_directories(crypto PRIVATE
    ${VillageSQLExtensionFramework_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Link OpenSSL
target_link_libraries(crypto PRIVATE ${OPENSSL_LIBRARIES})

# Create the VEB package
VEF_CREATE_VEB(
    NAME ${EXTENSION_NAME}
    LIBRARY_TARGET crypto
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
)
