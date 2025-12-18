cmake_minimum_required(VERSION 3.10)
project(native_sea)

if(DEFINED OPENSSL_PREFAB_DIR)
  set(OPENSSL_PREFAB "${OPENSSL_PREFAB_DIR}")
  set(OPENSSL_INCLUDE_DIR "${OPENSSL_PREFAB}/include")
  set(OPENSSL_LIB_DIR "${OPENSSL_PREFAB}/libs/android.${ANDROID_ABI}")

  add_library(openssl_crypto_prebuilt STATIC IMPORTED)
  set_target_properties(openssl_crypto_prebuilt PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_LIB_DIR}/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
  )
else()
  # Try to fall back to a system-provided crypto library if Prefab isn't provided.
  find_library(OPENSSL_CRYPTO_LIB crypto)
  if(OPENSSL_CRYPTO_LIB)
    add_library(openssl_crypto_prebuilt STATIC IMPORTED)
    set_target_properties(openssl_crypto_prebuilt PROPERTIES
      IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIB}"
    )
  endif()
endif()

add_library(native_sea SHARED
  digest.cpp
  pbkdf2.cpp
  native_seapair.cpp
  native_seacrypto.cpp
  native_seasign.cpp
)

target_include_directories(native_sea PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(TARGET openssl_crypto_prebuilt)
  target_link_libraries(native_sea PRIVATE openssl_crypto_prebuilt)
endif()

# Android logging
find_library(log-lib log)
if(log-lib)
  target_link_libraries(native_sea PRIVATE ${log-lib})
else()
  target_link_libraries(native_sea PRIVATE log)
endif()
