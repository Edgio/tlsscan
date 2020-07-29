# ------------------------------------------------------------------------------
# project setup
# ------------------------------------------------------------------------------
project(tlsscan)
# ------------------------------------------------------------------------------
# flags...
# ------------------------------------------------------------------------------
add_definitions(-Wall)
add_definitions(-Werror)
add_definitions(-Weffc++)
add_definitions(-Wno-deprecated-declarations)
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/sub/openssl/include
    ${CMAKE_SOURCE_DIR}/sub/openssl
)
# ------------------------------------------------------------------------------
# sources
# ------------------------------------------------------------------------------
SET(SRCS
    ndebug.cc
    host_info.cc
    conn.cc
    tls_conn.cc
    cert.cc
    missing_ciphersuites.cc
    protocol.cc
    scan.cc
    main.cc
)
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS)
# ------------------------------------------------------------------------------
# build and install
# ------------------------------------------------------------------------------
add_executable(tlsscan_cmd ${HDRS} ${SRCS})
add_dependencies(tlsscan_cmd submodule_openssl)
SET_TARGET_PROPERTIES(tlsscan_cmd PROPERTIES OUTPUT_NAME "tlsscan")
target_link_libraries(tlsscan_cmd
    ${DEBUG_LIBRARIES}
    ${CMAKE_SOURCE_DIR}/sub/openssl/libssl.a
    ${CMAKE_SOURCE_DIR}/sub/openssl/libcrypto.a
    dl
    pthread
)
install(TARGETS tlsscan_cmd
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
    COMPONENT Executables
)
