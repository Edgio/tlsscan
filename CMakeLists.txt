# ------------------------------------------------------------------------------
# Project setup
# ------------------------------------------------------------------------------
project(tlsscan)
cmake_minimum_required(VERSION 3.10)
# ------------------------------------------------------------------------------
# Build options
# ------------------------------------------------------------------------------
option(GCC_OPTIONS          "Command line options passed to gcc or 'native' to compile for this hardware" OFF)
option(FORTIFY              "Fortify Source GCC options" OFF)
option(DEBUG_MODE           "Compile in debug mode." OFF)
option(BUILD_SYMBOLS        "Build with Symbols" OFF)
option(BUILD_ASAN           "Build with Address Sanitizer" OFF)
option(BUILD_UBSAN          "Build with Undefined Behavior Sanitizer" OFF)
# ------------------------------------------------------------------------------
# Display the current settings
# ------------------------------------------------------------------------------
message(STATUS "Build Configuration:")
message("")
message("    Build Option                               Variable                Value                 ")
message("    -----------------------------------------------------------------------------------------")
message("    Debug mode:                                " "DEBUG_MODE              " ${DEBUG_MODE})
message("    Fortify Source:                            " "FORTIFY                 " ${FORTIFY})
message("    Install path:                              " "INSTALL_PREFIX          " ${CMAKE_INSTALL_PREFIX})
message("    Build Symbols                              " "BUILD_SYMBOLS           " ${BUILD_SYMBOLS})
message("    Build with Address Sanitizer:              " "BUILD_ASAN              " ${BUILD_ASAN})
message("    Build with Undefined Behavior Sanitizer:   " "BUILD_UBSAN             " ${BUILD_UBSAN})
message("")
# ------------------------------------------------------------------------------
# fortify options
# ------------------------------------------------------------------------------
if (FORTIFY)
  add_definitions(-D_FORTIFY_SOURCE=2 -O1 -fstack-protector-all -Wl,-z,relro,-z,now)
endif()
# ------------------------------------------------------------------------------
# ASAN
# ------------------------------------------------------------------------------
if (BUILD_ASAN)
  set(DEBUG_LIBRARIES asan ${DEBUG_LIBRARIES})
  add_definitions(-g3 -fno-omit-frame-pointer -fsanitize=address)
  set(DEBUG_MODE ON)
# ------------------------------------------------------------------------------
# UBSAN
# ------------------------------------------------------------------------------
elseif (BUILD_UBSAN)
  set(DEBUG_LIBRARIES ubsan ${DEBUG_LIBRARIES})
  add_definitions(-g3 -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover)
  set(DEBUG_MODE ON)
endif()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
set(LIBRARIES ${LIBRARIES} dl)
message(STATUS "Libraries: ${LIBRARIES}")
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
# make the cmake list variables into .deb-compatible strings
string(REPLACE ";" ", " CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS_LIST}")
string(REPLACE ";" ", " CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS "${CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS_LIST}")
# ------------------------------------------------------------------------------
# Optional flags
# ------------------------------------------------------------------------------
if (DEBUG_MODE)
  add_definitions(-O0 -g3)
else()
  add_definitions(-O2)
endif()
if (BUILD_SYMBOLS)
  add_definitions(-g3)
endif()
# ------------------------------------------------------------------------------
# ******************************************************************************
# external projects
# ******************************************************************************
# ------------------------------------------------------------------------------
include(ExternalProject)
# ------------------------------------------------------------------------------
# openssl
# ------------------------------------------------------------------------------
set(OPENSSL_COMPILER_FLAGS "-fPIC -DPURIFY")
if(OPENSSL_DEBUG)
    set(OPENSSL_COMPILER_FLAGS "no-asm -d -g3 -ggdb -gdwarf-4 -fno-inline -O0 -fno-omit-frame-pointer -fno-inline-functions -fPIC -DPURIFY")
    message('WARNING: Enabling OpenSSL debugging. DO NOT USE IN RELEASE BUILDS.')
endif()
set(OPENSSL_CONFIG_OPTIONS "shared ${OPENSSL_COMPILER_FLAGS} -DALLOW_ADH -DOPENSSL_MAX_TLS1_2_CIPHER_LENGTH=50 -DOPENSSL_TLS_SECURITY_LEVEL=0 no-idea no-mdc2 no-rc5 enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method")
# ----------------------------------------------------------
# avoid cmake inserting double quotes in the evaluated
# string in the CONFIGURE_COMMAND below
# ----------------------------------------------------------
separate_arguments(OPENSSL_CONFIG_OPTIONS_LIST UNIX_COMMAND "${OPENSSL_CONFIG_OPTIONS}")
ExternalProject_Add(submodule_openssl
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/sub/openssl
    BINARY_DIR ${CMAKE_SOURCE_DIR}/sub/openssl
    CONFIGURE_COMMAND ./config ${OPENSSL_CONFIG_OPTIONS_LIST}
    INSTALL_COMMAND ""
)
# ------------------------------------------------------------------------------
# Version
# ------------------------------------------------------------------------------
EXECUTE_PROCESS(COMMAND git describe --tags OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT ${VERSION} MATCHES ^[0-9]+.[0-9]+)
        message(FATAL_ERROR "Most recent tag '${VERSION}' does not match required version regex: ^[0-9]+.[0-9]+
Does it start with a number?")
endif()
add_definitions(-DTLSSCAN_VERSION="${VERSION}")
# ------------------------------------------------------------------------------
# Debian Package Support
# ------------------------------------------------------------------------------
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  SET(DISTRIBUTION "macOS")
else()
  EXECUTE_PROCESS(COMMAND lsb_release -cs OUTPUT_VARIABLE DISTRIBUTION OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_VERSION "${VERSION}-${DISTRIBUTION}")
SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
SET(CPACK_PACKAGE_FILE_NAME "tlsscan_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
SET(CPACK_DEBIAN_PACKAGE_NAME "tlsscan")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Reed Morrison")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TLS Protocol/Cipher Scanner.")
SET(CPACK_PACKAGE_DESCRIPTION "TLS Protocol/Cipher Scanner.")
message(STATUS "Package Configuration:")
message("")
message("    Option                                     Value                     ")
message("    ---------------------------------------------------------------------")
message("    Package Version:                           ${CPACK_DEBIAN_PACKAGE_VERSION}")
message("")
INCLUDE(CPack)
# ------------------------------------------------------------------------------
# include source and test directories
# ------------------------------------------------------------------------------
add_subdirectory(src)
# ------------------------------------------------------------------------------
# docs
# ------------------------------------------------------------------------------
add_custom_target(docs
    COMMAND doxygen ${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
)
