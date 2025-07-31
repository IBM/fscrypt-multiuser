cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_STANDARD "11")
set(C_STANDARD_REQUIRED ON)

project(fscrypt_multiuser "C")

set(fscrypt_multiuser_BUILDVERSION 1.0.1)

option(PAM_RULE_INSTALL "install the ubuntu-specific rule in pam-configs" OFF)
option(PAM_AUTH_FORCE_UPDATE "Run pam rules update after installing ubuntu-specific rule" OFF)
option(INSTALL_HEADERS "Install development headers" ON)
set(CMAKE_INSTALL_PAMDIR "security" CACHE STRING "Pam lib directory")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "CMake install prefix" FORCE)
endif()

include(GNUInstallDirs)

set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG_BUILD")
set(CMAKE_C_FLAGS "-fPIC -Wall -Werror -Wextra \
    -Wformat=2 -Wno-switch -Wcast-align -Wundef -Wcast-qual \
    -Wshadow -Wlogical-op -Wfloat-equal -Wbad-function-cast \
    -Wstrict-prototypes"
)

message("fscrypt_multiuser_BUILDVERSION = ${fscrypt_multiuser_BUILDVERSION}")
message("CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
message("PAM_RULE_INSTALL = ${PAM_RULE_INSTALL}")
message("PAM_AUTH_FORCE_UPDATE = ${PAM_AUTH_FORCE_UPDATE}")
message("INSTALL_HEADERS = ${INSTALL_HEADERS}")
message("CMAKE_INSTALL_PREFIX = ${CMAKE_INSTALL_PREFIX}")
message("CMAKE_INSTALL_BINDIR = ${CMAKE_INSTALL_BINDIR}")
message("CMAKE_INSTALL_LIBDIR = ${CMAKE_INSTALL_LIBDIR}")
message("CMAKE_INSTALL_SYSCONFDIR = ${CMAKE_INSTALL_SYSCONFDIR}")
message("CMAKE_INSTALL_INCLUDEDIR = ${CMAKE_INSTALL_INCLUDEDIR}")
message("CMAKE_INSTALL_DATAROOTDIR = ${CMAKE_INSTALL_DATAROOTDIR}")
message("CMAKE_INSTALL_RUNSTATEDIR = ${CMAKE_INSTALL_RUNSTATEDIR}")
message("CMAKE_INSTALL_PAMDIR = ${CMAKE_INSTALL_PAMDIR}")

set(fscrypt_multiuser_LOCKSTATEDIR "/${CMAKE_INSTALL_RUNSTATEDIR}/lock")
message("fscrypt_multiuser_LOCKSTATEDIR = ${fscrypt_multiuser_LOCKSTATEDIR}")

set(fscrypt_multiuser_CONFIG_PATH "/${CMAKE_INSTALL_SYSCONFDIR}/fscrypt_multiuser.conf")
message("fscrypt_multiuser_CONFIG_PATH = ${fscrypt_multiuser_CONFIG_PATH}")

configure_file(
    "templates/BUILD_PARAMS.template"
    "${CMAKE_BINARY_DIR}/include/BUILD_PARAMS.h"
)

include_directories("inc")
include_directories("${CMAKE_BINARY_DIR}/include")

# Exports target OpenSSL::Crypto
find_package(OpenSSL REQUIRED)
message("Found OpenSSL version ${OPENSSL_VERSION}")

# set(CMAKE_STATIC_LIBRARY_PREFIX "")

add_library(pam_fscrypt_multiuser MODULE "src/pam_fscrypt_multiuser.c" "src/fscrypt_utils.c" "src/hasher.c")
set_target_properties(pam_fscrypt_multiuser PROPERTIES PREFIX "")
target_link_libraries(pam_fscrypt_multiuser PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
install(TARGETS pam_fscrypt_multiuser DESTINATION "${CMAKE_INSTALL_LIBDIR}/${CMAKE_INSTALL_PAMDIR}")

add_library(fscrypt_pam_subprocess_hook SHARED "src/fscrypt_pam_subprocess_hook.c")
set_target_properties(fscrypt_pam_subprocess_hook PROPERTIES PREFIX "")
install(TARGETS fscrypt_pam_subprocess_hook DESTINATION ${CMAKE_INSTALL_LIBDIR})

add_executable(fscrypt_generate_kek "src/fscrypt_generate_kek.c" "src/hasher.c")
target_link_libraries(fscrypt_generate_kek PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
install(TARGETS fscrypt_generate_kek DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(wraptest "src/wraptest.c" "src/fscrypt_utils.c" "src/hasher.c")
target_link_libraries(wraptest PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
# install(TARGETS wraptest DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(fscrypt_setup "src/fscrypt_setup.c" "src/fscrypt_utils.c" "src/hasher.c")
target_link_libraries(fscrypt_setup PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
install(TARGETS fscrypt_setup DESTINATION ${CMAKE_INSTALL_BINDIR})


if(INSTALL_HEADERS)
    install(FILES "inc/fscrypt_pam_hook.h" DESTINATION ${CMAKE_INSTALL_FULL_INCLUDEDIR})
endif()

if(PAM_RULE_INSTALL)
    set(fscrypt_multiuser_PAMCONFIGDIR "${CMAKE_INSTALL_DATAROOTDIR}/pam-configs")
    message("Pam configuration install to ${fscrypt_multiuser_PAMCONFIGDIR}")
    install(FILES "pam/fscrypt-multiuser-rule" DESTINATION ${fscrypt_multiuser_PAMCONFIGDIR})

    if(PAM_AUTH_FORCE_UPDATE)
        install(CODE "execute_process(COMMAND pam-auth-update --force --package COMMAND echo pam-auth-update complete)")
    endif()
endif()
