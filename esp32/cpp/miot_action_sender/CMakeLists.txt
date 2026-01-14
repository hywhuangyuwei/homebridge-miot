cmake_minimum_required(VERSION 3.16)
project(miot_action_sender LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(miot_action_sender main.cpp)

# macOS: use CommonCrypto (no extra link flags typically needed)
if(APPLE)
  target_compile_definitions(miot_action_sender PRIVATE MIOT_USE_COMMONCRYPTO=1)
endif()

# Embedded/Linux option: build with mbedTLS (provide include/lib paths via toolchain)
# -DMIOT_USE_MBEDTLS=1 and link mbedtls/mbedcrypto.
option(MIOT_USE_MBEDTLS "Use mbedTLS for AES/MD5" OFF)
if(MIOT_USE_MBEDTLS)
  target_compile_definitions(miot_action_sender PRIVATE MIOT_USE_MBEDTLS=1)
  find_library(MBEDTLS_LIB mbedtls)
  find_library(MBEDCRYPTO_LIB mbedcrypto)
  if(NOT MBEDTLS_LIB OR NOT MBEDCRYPTO_LIB)
    message(FATAL_ERROR "mbedTLS libs not found. Provide toolchain/library paths or disable MIOT_USE_MBEDTLS.")
  endif()
  target_link_libraries(miot_action_sender PRIVATE ${MBEDTLS_LIB} ${MBEDCRYPTO_LIB})
endif()
