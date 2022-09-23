//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    protocol.cc
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "def.h"
#include "protocol.h"
#include "conn.h"
#include "tls_conn.h"
#include "missing_ciphersuites.h"
#include "ndebug.h"
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <list>
#include <vector>
//! ----------------------------------------------------------------------------
//! defines...
//! ----------------------------------------------------------------------------
#define _MAX_CIPHERS_STR_LEN  65536
#define _TLSV13_CIPHERSUITES    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"
#define _CIPHERSUITE_LIST_ALL   "ALL:COMPLEMENTOFALL"
#define _CIPHERSUITE_LIST_OTHER "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA:SRP-DSS-AES-256-CBC-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:CAMELLIA256-SHA:SRP-DSS-AES-128-CBC-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:PSK-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:PSK-3DES-EDE-CBC-SHA"
#define _TLS_RECORD_SIZE        (16*1024*1024)
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
// ---------------------------------------------------------
// append vb
// ---------------------------------------------------------
#define _VB_APPEND_VB(_dest, _src) _dest.insert(_dest.end(), _src.begin(), _src.end())
// ---------------------------------------------------------
// append obj
// ---------------------------------------------------------
#define _VB_APPEND_OBJ(_vb, _obj) \
        _vb.insert(_vb.end(), (uint8_t *)(&_obj), (uint8_t *)(&_obj)+sizeof(_obj))
#define _VB_ASSIGN_OBJ(_vb, _obj, _off) \
        std::copy((uint8_t *)(&_obj), (uint8_t *)(&_obj)+sizeof(_obj), _vb.begin() + _off)
// ---------------------------------------------------------
// append value
// ---------------------------------------------------------
#define _VB_APPEND_UINT8(_vb, _val) do { \
        uint8_t _tmp = (uint8_t)(_val); \
        _vb.insert(_vb.end(), (uint8_t *)(&_tmp), (uint8_t *)(&_tmp)+sizeof(_tmp)); \
} while(0)
#define _VB_APPEND_UINT16(_vb, _val) do { \
        uint16_t _tmp = htons((uint16_t)(_val)); \
        _vb.insert(_vb.end(), (uint8_t *)(&_tmp), (uint8_t *)(&_tmp)+sizeof(_tmp)); \
} while(0)
#define _VB_APPEND_UINT32(_vb, _val) do { \
        uint32_t _tmp = (uint32_t)(_val); \
        _vb.insert(_vb.end(), (uint8_t *)(&_tmp), (uint8_t *)(&_tmp)+sizeof(_tmp)); \
} while(0)
// ---------------------------------------------------------
// append str
// ---------------------------------------------------------
#define _VB_APPEND_STR(_vb, _str) \
        _vb.insert(_vb.end(), (uint8_t *)(_str.c_str()), (uint8_t *)(_str.c_str())+_str.length())
// ---------------------------------------------------------
// assign value
// ---------------------------------------------------------
#define _VB_ASSIGN_UINT8(_vb, _off, _val) do { \
        uint8_t _tmp = (uint8_t)(_val); \
        std::copy((uint8_t *)(&_tmp), (uint8_t *)(&_tmp)+sizeof(_tmp), _vb.begin() + _off); \
} while(0)
#define _VB_ASSIGN_UINT16(_vb, _off, _val) do { \
        uint16_t _tmp = htons((uint16_t)(_val)); \
        std::copy((uint8_t *)(&_tmp), (uint8_t *)(&_tmp)+sizeof(_tmp), _vb.begin() + _off); \
} while(0)
// ---------------------------------------------------------
// display
// ---------------------------------------------------------
#define _VB_DISPLAY(_vb) mem_display(&_vb[0], _vb.size())
// ---------------------------------------------------------
// update length
// ---------------------------------------------------------
#define _VB_EXT_UPDATE_LEN(_vb) do { \
        uint16_t _tmp1 = (uint16_t)(_vb.size() - sizeof(uint16_t)); \
        uint16_t _tmp = htons((uint16_t)(_tmp1)); \
        std::copy((uint8_t *)(&_tmp), (uint8_t *)(&_tmp)+sizeof(_tmp), _vb.begin() + 0); \
} while(0)
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::vector<uint8_t> vb_t;
//! ----------------------------------------------------------------------------
//! ext: tlsv13 cipher suites
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_tlsv13_cipher_suites[] =
{
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0x13, 0x04, // TLS_AES_128_CCM_SHA256
        0x13, 0x05, // TLS_AES_128_CCM_8_SHA256
};
//! ----------------------------------------------------------------------------
//! ext: ec_point_formats
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_ec_points_formats[] =
{
        0x00, 0x0b, // ext: ec_point_formats (11)
        0x00, 0x04, // ext: length (4)
        0x03,       // ec point formats length (3)
        0x00,       // Uncompressed
        0x01,       // ansiX962_compressed_prime
        0x02,       // ansiX962_compressed_char2
};
//! ----------------------------------------------------------------------------
//! ext: session ticket
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_session_ticket[] =
{
        0x00, 0x23, // ext: session ticket tls (35)
        0x00, 0x00, // ext: length (0)
};
//! ----------------------------------------------------------------------------
//! ext: signature algorithms
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_sig_algos[] =
{
        0x00, 0x0d, // ext: signature_algorithms (13)
        0x00, 0x30, // ext: Length (48)
        0x00, 0x2e, // signature hash algorithms length (46)
        0x08, 0x04, // rsa_pss_rsae_sha256
        0x08, 0x05, // rsa_pss_rsae_sha384
        0x08, 0x06, // rsa_pss_rsae_sha512
        0x08, 0x07, // ed25519
        0x08, 0x08, // ed448
        0x08, 0x09, // rsa_pss_pss_sha256
        0x08, 0x0a, // rsa_pss_pss_sha384
        0x08, 0x0b, // rsa_pss_pss_sha512
        0x06, 0x01, // rsa_pkcs1_sha512
        0x06, 0x02, // SHA512 DSA
        0x06, 0x03, // ecdsa_secp521r1_sha512
        0x05, 0x01, // rsa_pkcs1_sha384
        0x05, 0x02, // SHA384 DSA
        0x05, 0x03, // ecdsa_secp384r1_sha384
        0x04, 0x01, // rsa_pkcs1_sha256"
        0x04, 0x02, // SHA256 DSA
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x03, 0x01, // SHA224 ECDSA
        0x03, 0x02, // SHA224 DSA
        0x03, 0x03, // SHA224 ECDSA
        0x02, 0x01, // rsa_pkcs1_sha1
        0x02, 0x02, // SHA1 DSA
        0x02, 0x03, // ecdsa_sha1
};
//! ----------------------------------------------------------------------------
//! ext: supported groups
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_supported_groups[] =
{
        0x00, 0x0a, // ext: supported_groups (10)
        0x00, 0x16, // ext: length (22)
        0x00, 0x14, // supported Groups List Length (20)
        0x00, 0x17, // secp256r1
        0x00, 0x19, // secp521r1
        0x00, 0x18, // secp384r1
        0x00, 0x1d, // X25519
        0x00, 0x1e, // X448
        0x01, 0x00, // FFDHE2048
        0x01, 0x01, // FFDHE3072
        0x01, 0x02, // FFDHE4096
        0x01, 0x03, // FFDHE6144
        0x01, 0x04, // FFDHE8192
};
//! ----------------------------------------------------------------------------
//! ext: default key share
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_default_key_share[] =
{
        0x00, 0x33, // ext: key_share (51)
        0x00, 0x26, // ext: length (38)
        0x00, 0x24, // Key Share List Length (36)
        0x00, 0x1d, // Group ID (X25519)
        0x00, 0x20, // Key Exchange Length (32)
};
//! ----------------------------------------------------------------------------
//! ext: tlsv1.3 supported version
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_tlsv13[] =
{
        0x00, 0x2b, // ext: supported_versions (43)
        0x00, 0x03, // ext: Length
        0x02,       // supported versions Length
        0x03, 0x04, // supported version: TLS v1.3
};
//! ----------------------------------------------------------------------------
//! ext: sig algo: add signature_algorithms extension.
//!      only add one group testing for.
//! ----------------------------------------------------------------------------
static const uint8_t g_blk_ext_sig_algo[] =
{
        0x00, 0x0d, // ext: signature_algorithms (13)
        0x00, 0x04, // ext: Length (4)
        0x00, 0x02, // signature hash algorithms list length (2)
};
//! ----------------------------------------------------------------------------
//! protocol strings
//! ----------------------------------------------------------------------------
static const char *g_protocol_strings[] =
{
#define _XX(num, name, string) #string,
        PROTOCOL_MAP(_XX)
#undef _XX
};
//! ----------------------------------------------------------------------------
//! tlsv12
//! ----------------------------------------------------------------------------
static const uint8_t g_tlsv12_opt[] = {
        0x00, 0x0a, // ext: supported_groups (10)
        0x00, 0x1c, // ext: length (28)
        0x00, 0x1a, // Supported Groups List Length (26)
        0x00, 0x17, // secp256r1
        0x00, 0x19, // secp521r1
        0x00, 0x1c, // brainpoolP512r1
        0x00, 0x1b, // brainpoolP384r1
        0x00, 0x18, // secp384r1
        0x00, 0x1a, // brainpoolP256r1
        0x00, 0x16, // secp256k1
        0x00, 0x0e, // sect571r1
        0x00, 0x0d, // sect571k1
        0x00, 0x0b, // sect409k1
        0x00, 0x0c, // sect409r1
        0x00, 0x09, // sect283k1
        0x00, 0x0a, // sect283r1
};
//! ----------------------------------------------------------------------------
//! tlsv13
//! ----------------------------------------------------------------------------
static const uint8_t g_tlsv13_opt[] = {
        0x00, 0x0a, // ext: supported_groups (10)
        0x00, 0x16, // ext: length (22)
        0x00, 0x14, // Supported Groups List Length (20)
        0x00, 0x17, // secp256r1
        0x00, 0x19, // secp521r1
        0x00, 0x18, // secp384r1
        0x00, 0x1d, // X25519
        0x00, 0x1e, // X448
        0x01, 0x00, // FFDHE2048
        0x01, 0x01, // FFDHE3072
        0x01, 0x02, // FFDHE4096
        0x01, 0x03, // FFDHE6144
        0x01, 0x04, // FFDHE8192
};
//! ----------------------------------------------------------------------------
//! sslv2 client l_hello
//! ----------------------------------------------------------------------------
static const uint8_t g_sslv2_hello[] = {
        0x80,
        0x34,             // Length: 52
        0x01,             // Handshake Message Type: client hello
        0x00, 0x02,       // Version: SSL 2.0
        0x00, 0x1b,       // Cipher Spec Length: 27
        0x00, 0x00,       // Session ID Length: 0
        0x00, 0x10,       // Challenge Length: 16
        0x05, 0x00, 0x80, // SSL2_IDEA_128_CBC_WITH_MD5
        0x03, 0x00, 0x80, // SSL2_RC2_128_CBC_WITH_MD5
        0x01, 0x00, 0x80, // SSL2_RC4_128_WITH_MD5
        0x07, 0x00, 0xc0, // SSL2_DES_192_EDE3_CBC_WITH_MD5
        0x08, 0x00, 0x80, // SSL2_RC4_64_WITH_MD5
        0x06, 0x00, 0x40, // SSL2_DES_64_CBC_WITH_MD5
        0x04, 0x00, 0x80, // SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
        0x02, 0x00, 0x80, // SSL2_RC4_128_EXPORT40_WITH_MD5
        0x00, 0x00, 0x00, // TLS_NULL_WITH_NULL_NULL
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f // Challenge
};
//! ----------------------------------------------------------------------------
//! sslv3 client l_hello pt 1
//! ----------------------------------------------------------------------------
static const uint8_t g_sslv3_hello_pt1[] =
{
        0x16,             // Content Type: Handshake (22)
        0x03, 0x00,       // Version SSL 3.0
        0x00, 0xe8,       // Length: 232
        0x01,             // Handshake Type: client hello
        0x00, 0x00, 0xe4, // Length: 228
        0x03, 0x00,       // Version: SSL 3.0
};
//! ----------------------------------------------------------------------------
//! sslv3 client l_hello pt 2
//! ----------------------------------------------------------------------------
static const uint8_t g_sslv3_hello_pt2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, // Random bytes
        0x00,       // Session ID Length
        0x00, 0xbc, // Cipher Suites Length: 188
        0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xc0, 0x0a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        0x00, 0x39, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x38, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        0x00, 0x37, // TLS_DH_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x36, // TLS_DH_DSS_WITH_AES_256_CBC_SHA
        0x00, 0x88, // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
        0x00, 0x87, // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
        0x00, 0x86, // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
        0x00, 0x85, // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
        0xc0, 0x19, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
        0x00, 0x3a, // TLS_DH_anon_WITH_AES_256_CBC_SHA
        0x00, 0x89, // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
        0xc0, 0x0f, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        0xc0, 0x05, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x84, // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
        0x00, 0x95, // TLS_RSA_PSK_WITH_AES_256_CBC_SHA
        0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc0, 0x09, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0x00, 0x33, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x32, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        0x00, 0x31, // TLS_DH_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x30, // TLS_DH_DSS_WITH_AES_128_CBC_SHA
        0x00, 0x9a, // TLS_DHE_RSA_WITH_SEED_CBC_SHA
        0x00, 0x99, // TLS_DHE_DSS_WITH_SEED_CBC_SHA
        0x00, 0x98, // TLS_DH_RSA_WITH_SEED_CBC_SHA
        0x00, 0x97, // TLS_DH_DSS_WITH_SEED_CBC_SHA
        0x00, 0x45, // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
        0x00, 0x44, // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
        0x00, 0x43, // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
        0x00, 0x42, // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
        0xc0, 0x18, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
        0x00, 0x34, // TLS_DH_anon_WITH_AES_128_CBC_SHA
        0x00, 0x9b, // TLS_DH_anon_WITH_SEED_CBC_SHA
        0x00, 0x46, // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
        0xc0, 0x0e, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        0xc0, 0x04, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x96, // TLS_RSA_WITH_SEED_CBC_SHA
        0x00, 0x41, // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
        0x00, 0x07, // TLS_RSA_WITH_IDEA_CBC_SHA
        0x00, 0x94, // TLS_RSA_PSK_WITH_AES_128_CBC_SHA
        0xc0, 0x11, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
        0xc0, 0x07, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        0x00, 0x66, // TLS_DHE_DSS_WITH_RC4_128_SHA
        0xc0, 0x16, // TLS_ECDH_anon_WITH_RC4_128_SHA
        0x00, 0x18, // TLS_DH_anon_WITH_RC4_128_MD5
        0xc0, 0x0c, // TLS_ECDH_RSA_WITH_RC4_128_SHA
        0xc0, 0x02, // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
        0x00, 0x05, // TLS_RSA_WITH_RC4_128_SHA
        0x00, 0x04, // TLS_RSA_WITH_RC4_128_MD5
        0x00, 0x92, // TLS_RSA_PSK_WITH_RC4_128_SHA
        0xc0, 0x12, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        0xc0, 0x08, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x16, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x13, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        0x00, 0x10, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x0d, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
        0xc0, 0x17, // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
        0x00, 0x1b, // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
        0xc0, 0x0d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
        0xc0, 0x03, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x93, // TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
        0x00, 0x63, // TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
        0x00, 0x15, // TLS_DHE_RSA_WITH_DES_CBC_SHA
        0x00, 0x12, // TLS_DHE_DSS_WITH_DES_CBC_SHA
        0x00, 0x0f, // TLS_DH_RSA_WITH_DES_CBC_SHA
        0x00, 0x0c, // TLS_DH_DSS_WITH_DES_CBC_SHA
        0x00, 0x1a, // TLS_DH_anon_WITH_DES_CBC_SHA
        0x00, 0x62, // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
        0x00, 0x09, // TLS_RSA_WITH_DES_CBC_SHA
        0x00, 0x61, // TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5
        0x00, 0x65, // TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
        0x00, 0x64, // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
        0x00, 0x60, // TLS_RSA_EXPORT1024_WITH_RC4_56_MD5
        0x00, 0x14, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x11, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x0e, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x0b, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x19, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x08, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x06, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        0x00, 0x17, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
        0x00, 0x03, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0xc0, 0x10, // TLS_ECDHE_RSA_WITH_NULL_SHA
        0xc0, 0x06, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
        0xc0, 0x15, // TLS_ECDH_anon_WITH_NULL_SHA
        0xc0, 0x0b, // TLS_ECDH_RSA_WITH_NULL_SHA
        0xc0, 0x01, // TLS_ECDH_ECDSA_WITH_NULL_SHA
        0x00, 0x02, // TLS_RSA_WITH_NULL_SHA
        0x00, 0x01, // TLS_RSA_WITH_NULL_MD5
        0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        0x02,       // Compression Methods Length: 2
        0x01, 0x00, // DEFLATE, none
};
//! ----------------------------------------------------------------------------
//! util
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
const char* get_protocol_str(protocol_t a_m)
{
        return ELEM_AT(g_protocol_strings, a_m, "<unknown>");
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
long get_protocol_opt_flag(protocol_t a_protocol)
{
        switch(a_protocol)
        {
        case PROTOCOL_SSLv2:   { return PROTOCOL_OP_FLAG_SSLv2;   break; }
        case PROTOCOL_SSLv3:   { return PROTOCOL_OP_FLAG_SSLv3;   break; }
        case PROTOCOL_TLSv1:   { return PROTOCOL_OP_FLAG_TLSv1;   break; }
        case PROTOCOL_TLSv1_1: { return PROTOCOL_OP_FLAG_TLSv1_1; break; }
        case PROTOCOL_TLSv1_2: { return PROTOCOL_OP_FLAG_TLSv1_2; break; }
        case PROTOCOL_TLSv1_3: { return PROTOCOL_OP_FLAG_TLSv1_3; break; }
        case PROTOCOL_NONE:    { return PROTOCOL_OP_FLAG_ALL;     break; }
        default:               { return PROTOCOL_OP_FLAG_ALL;     break; }
        }
}
//! ----------------------------------------------------------------------------
//! \details: returns byte string w/ list of all ciphersuites registered by IANA.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t vb_gen_cipher_suites(vb_t& ao_cipher_suites, protocol_t a_protocol)
{
        ao_cipher_suites.clear();
        // -------------------------------------------------
        // if tlsv1.3, return smaller v1.3-specific list.
        // -------------------------------------------------
        if(a_protocol == PROTOCOL_TLSv1_3)
        {
                _VB_APPEND_OBJ(ao_cipher_suites, g_blk_tlsv13_cipher_suites);
                return STATUS_OK;
        }
        // -------------------------------------------------
        // append from missing ciphers
        // -------------------------------------------------
        // -hack!!! -presumes len of g_missing_ciphersuites
        uint32_t l_len = 600;
        for(uint32_t i_c = 0; i_c < l_len; ++i_c)
        {
                // skip private cipher prefix
                const char* l_p = g_missing_ciphersuites[i_c].m_protocol_name;
                if(strstr(l_p, "PRIVATE_CIPHER_"))
                {
                        continue;
                }
                // append
                uint16_t l_id = g_missing_ciphersuites[i_c].m_id;
                _VB_APPEND_UINT16(ao_cipher_suites, l_id);
        }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: adds default key_share extension.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void vb_gen_tls_ext_add_default_key_share(vb_t& ao_vb)
{
        // -------------------------------------------------
        // append default key share
        // -------------------------------------------------
        _VB_APPEND_OBJ(ao_vb, g_blk_ext_default_key_share);
        // -------------------------------------------------
        // add 32 bytes of (bogus) X25519 key share.
        // -------------------------------------------------
        srand(time(NULL) ^ 0xbeefdead);
        for(int i = 0; i < 32; ++i)
        {
                uint8_t l_c = (uint8_t)rand();
                _VB_APPEND_UINT8(ao_vb, l_c);
        }
        _VB_EXT_UPDATE_LEN(ao_vb);
}
//! ----------------------------------------------------------------------------
//! \details: retrieves a tls handshake record
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t get_tls_handshake_record(uint8_t* ao_record, conn& a_conn)
{
        if(!ao_record)
        {
                //NDBG_PRINT("...\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // read first 5 bytes for length of rest of record.
        // -------------------------------------------------
        int32_t l_b_read = 0;
        uint16_t l_to_read = 5;
        uint16_t l_read = 0;
        while(l_to_read)
        {
                errno = 0;
                l_b_read = recv(a_conn.m_fd, ao_record+l_read, l_to_read, 0);
                //NDBG_PRINT("l_b_read:     %d\n", l_b_read);
                if(l_b_read <= 0)
                {
                        //NDBG_PRINT("error: performing recv: reason[%d]: %s\n", errno, strerror(errno));
                        return STATUS_ERROR;
                }
                l_to_read -= (uint16_t)l_b_read;
                l_read += (uint16_t)l_b_read;
        }
        if(l_read != 5)
        {
                //NDBG_PRINT("error: performing recv(5 bytes): reason[%d]: %s\n", errno, strerror(errno));
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // ensure content type is handshake (22).
        // -------------------------------------------------
        //NDBG_PRINT("ao_record[0]: 0x%0X\n", ao_record[0]);
        if(ao_record[0] != 0x16)
        {
                //NDBG_PRINT("error: ao_record[0]: 0x%0X\n", ao_record[0]);
                //mem_display(ao_record, l_b_read);
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // get length of record.
        // -------------------------------------------------
        uint16_t l_r_len = 0;
        l_r_len = (ao_record[3] << 8) | (ao_record[4]);
        //NDBG_PRINT("l_r_len:      %d\n", l_r_len);
        // -------------------------------------------------
        // read in rest of record.
        // -------------------------------------------------
        l_to_read = l_r_len;
        l_read = 5;
        while(l_to_read)
        {
                errno = 0;
                l_b_read = recv(a_conn.m_fd, ao_record+l_read, l_to_read, 0);
                //NDBG_PRINT("l_b_read:     %d\n", l_b_read);
                if(l_b_read <= 0)
                {
                        //NDBG_PRINT("error: performing recv: reason[%d]: %s\n", errno, strerror(errno));
                        return STATUS_ERROR;
                }
                l_to_read -= (uint16_t)l_b_read;
                l_read += (uint16_t)l_b_read;
        }
        if(l_read != 5+l_r_len)
        {
                //NDBG_PRINT("error: performing recv(%d bytes): reason[%d]: %s\n", 5+l_r_len, errno, strerror(errno));
                return STATUS_ERROR;
        }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: read server hello
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t get_server_hello(uint8_t* ao_hello, conn& a_conn)
{
        if(!ao_hello)
        {
                //NDBG_PRINT("error: \n");
                return STATUS_ERROR;
        }
        int32_t l_s;
        // -------------------------------------------------
        // get handshake record
        // -------------------------------------------------
        l_s = get_tls_handshake_record(ao_hello, a_conn);
        if(l_s != STATUS_OK)
        {
                //NDBG_PRINT("error: \n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // ensure handshake type is server hello (2).
        // -------------------------------------------------
        if(ao_hello[5] != 0x02)
        {
                //NDBG_PRINT("error: \n");
                return STATUS_ERROR;
        }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: creates a basic set of tls extensions,
//!           including:
//!             sni,
//!             ec_point_formats,
//!             session ticket,
//!             signature_algorithms.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t vb_gen_tls_ext(vb_t& ao_vb, const std::string& a_sni_name, bool add_sig_algo = false)
{
        // -------------------------------------------------
        // append length (to be filled in later).
        // -------------------------------------------------
        uint16_t l_tmp_ushort = 0;
        _VB_APPEND_OBJ(ao_vb, l_tmp_ushort);
        // -------------------------------------------------
        // ext: server name
        // -------------------------------------------------
        uint16_t l_sni_len = a_sni_name.length();
        // ext: server_name
        _VB_APPEND_UINT16(ao_vb, 0x0000);
        // ext: length
        _VB_APPEND_UINT16(ao_vb, (l_sni_len + 5));
        // ext: sni list length
        _VB_APPEND_UINT16(ao_vb, (l_sni_len + 3));
        // ext: server name type: host name
        _VB_APPEND_UINT8(ao_vb, 0x00);
        // ext: hostname length
        _VB_APPEND_UINT16(ao_vb, (l_sni_len));
        // ext: hostname
        _VB_APPEND_STR(ao_vb, a_sni_name);
        // -------------------------------------------------
        // ext: ec_point_formats
        // -------------------------------------------------
        _VB_APPEND_OBJ(ao_vb, g_blk_ext_ec_points_formats);
        // -------------------------------------------------
        // ext: session ticket
        // -------------------------------------------------
        _VB_APPEND_OBJ(ao_vb, g_blk_ext_session_ticket);
        // -------------------------------------------------
        // ext: no sig algo
        // -------------------------------------------------
        if(!add_sig_algo)
        {
                goto done;
        }
        // -------------------------------------------------
        // ext: sig algo
        // -------------------------------------------------
        _VB_APPEND_OBJ(ao_vb, g_blk_ext_sig_algos);
        // -------------------------------------------------
        // ext: set length
        // -------------------------------------------------
done:
        _VB_EXT_UPDATE_LEN(ao_vb);
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: returns a byte string (which caller must later bs_free())
//!           containing a TLS client hello message.  The 'tls_version' must be
//!           one of TLSv1_? constants.  The specified ciphersuite list and
//!           TLS extensions will be included.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t vb_gen_client_hello(vb_t& ao_clnt_hello,
                                   protocol_t a_protocol,
                                   const vb_t& a_cipher_suites,
                                   const vb_t& a_tls_ext)
{
        // tls record version low byte
        uint8_t l_rec_ver_lb = 1;
        // tls handshake version low bytes
        uint8_t l_hsk_ver_lb = 1;
        // -------------------------------------------------
        // For TLSv1.0, 1.1, and 1.2:
        // TLS Record version and Handshake version are
        // same.
        //
        // For TLSv1.3:
        // TLS Record claims to be TLSv1.0 and handshake
        // claims to be TLSv1.2.
        // -for compatibility of buggy middleware most
        //  implementations follow.
        // -------------------------------------------------
        switch(a_protocol)
        {
        case PROTOCOL_TLSv1:
        {
                l_rec_ver_lb += 0;
                l_hsk_ver_lb += 0;
                break;
        }
        case PROTOCOL_TLSv1_1:
        {
                l_rec_ver_lb += 1;
                l_hsk_ver_lb += 1;
                break;
        }
        case PROTOCOL_TLSv1_2:
        {
                l_rec_ver_lb += 2;
                l_hsk_ver_lb += 2;
                break;
        }
        case PROTOCOL_TLSv1_3:
        {
                l_rec_ver_lb = 1;
                l_hsk_ver_lb = 3;
                break;
        }
        default:
        {
                l_rec_ver_lb += 2;
                l_hsk_ver_lb += 2;
                break;
        }
        }
        // -------------------------------------------------
        // byte vector for client hello and tls extensions.
        // -------------------------------------------------
        ao_clnt_hello.clear();
        // -------------------------------------------------
        // Build TLSv1 Record with client hello message.
        // -------------------------------------------------
        uint8_t l_rec[] =
        {
                0x16,               // content Type: Handshake (22)
                0x03, l_rec_ver_lb, // version: TLS 1.x
                0x00, 0x00,         // length (to be filled in later)
                0x01,               // handshake Type: client hello
                0x00, 0x00, 0x00,   // length (to be filled in later)
                0x03, l_hsk_ver_lb, // version: TLS 1.x
        };
        _VB_APPEND_OBJ(ao_clnt_hello, l_rec);
        // -------------------------------------------------
        // "random" 32 bytes.
        // -------------------------------------------------
        time_t l_now = time(NULL);
        uint32_t l_rand = htonl(l_now);
        // first 4 bytes is timestamp.
        _VB_APPEND_UINT32(ao_clnt_hello, l_rand);
        // random bytes.
        for(int i = 1; i < 8; ++i)
        {
                l_rand = l_rand + (l_now ^ (uint32_t)((~(i + 0) << 24) | (~(i + 1) << 16) | (~(i + 2) << 8) | (~(i + 3) << 0)));
                _VB_APPEND_UINT32(ao_clnt_hello, l_rand);
        }
        // -------------------------------------------------
        // Session ID Length: 0
        // -------------------------------------------------
        uint8_t l_s_id = 0;
        _VB_APPEND_UINT8(ao_clnt_hello, l_s_id);
        // -------------------------------------------------
        // add length of ciphersuites list to client hello.
        // -------------------------------------------------
        uint16_t l_cipher_suites_len = (uint16_t)a_cipher_suites.size();
        _VB_APPEND_UINT16(ao_clnt_hello, l_cipher_suites_len);
        // -------------------------------------------------
        // add ciphersuite list.
        // -------------------------------------------------
        _VB_APPEND_VB(ao_clnt_hello, a_cipher_suites);
        // -------------------------------------------------
        // add compression options.
        // -------------------------------------------------
        static const uint8_t s_compression_opt[] =
        {
                0x01, // Compression Methods Length (1)
                0x00  // Compression Method: null (0)
        };
        _VB_APPEND_OBJ(ao_clnt_hello, s_compression_opt);
        // -------------------------------------------------
        // add extensions to client hello.
        // -------------------------------------------------
        _VB_APPEND_VB(ao_clnt_hello, a_tls_ext);
        // -------------------------------------------------
        // set length of client hello.
        // -------------------------------------------------
        uint16_t l_clnt_hello_len = (uint16_t)(ao_clnt_hello.size());
        _VB_ASSIGN_UINT8(ao_clnt_hello, 6, 0);
        _VB_ASSIGN_UINT16(ao_clnt_hello, 7, (l_clnt_hello_len-9));
        // -------------------------------------------------
        // set length of Record Layer.
        // -------------------------------------------------
        _VB_ASSIGN_UINT16(ao_clnt_hello, 3, (l_clnt_hello_len-5));
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_sslv2(const host_info& a_host_info)
{
        // -------------------------------------------------
        // create a socket to target.
        // -------------------------------------------------
        int32_t l_s;
        conn l_conn(a_host_info);
        l_s = l_conn.connect();
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // send SSLv2 client l_hello
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, g_sslv2_hello, sizeof(g_sslv2_hello), 0);
        if(l_s <= 0)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // read partial response.
        // -------------------------------------------------
        char l_resp[8] = {0};
        l_s = recv(l_conn.m_fd, l_resp, sizeof(l_resp), 0);
        if(l_s != sizeof(l_resp))
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // verify SSL v2.
        // 1. handshakemMessage server l_hello (0x04)
        // 2. version is SSL 2.0: (0x00, 0x02)
        // -------------------------------------------------
        if((l_resp[2] == 0x04) &&
           (l_resp[5] == 0x00) && (l_resp[6] == 0x02))
        {
                return STATUS_OK;
        }
        return STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_sslv3(const host_info& a_host_info)
{
        // -------------------------------------------------
        // create a socket to target.
        // -------------------------------------------------
        int32_t l_s;
        conn l_conn(a_host_info);
        l_s = l_conn.connect();
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // send SSLv3 client l_hello pt1
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, g_sslv3_hello_pt1, sizeof(g_sslv3_hello_pt1), 0);
        if(l_s <= 0)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // timestamp
        // -------------------------------------------------
        uint32_t l_ts = 0;
        uint8_t l_ts_b[4] = {0};
        // current time stamp.
        l_ts = htonl(time(NULL));
        l_ts_b[0] = l_ts & 0xff;
        l_ts_b[1] = (l_ts >> 8) & 0xff;
        l_ts_b[2] = (l_ts >> 16) & 0xff;
        l_ts_b[3] = (l_ts >> 24) & 0xff;
        // -------------------------------------------------
        // send timestamp
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, l_ts_b, sizeof(l_ts_b), 0);
        if(l_s <= 0)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // send SSLv3 client l_hello pt2
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, g_sslv3_hello_pt2, sizeof(g_sslv3_hello_pt2), 0);
        if(l_s <= 0)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // read partial response.
        // -------------------------------------------------
        char l_resp[16] = {0};
        l_s = recv(l_conn.m_fd, l_resp, sizeof(l_resp), 0);
        if(l_s != sizeof(l_resp))
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // examine response:
        //   1. Content Type is Handshake (22)
        //   2. Version is SSL 3.0
        //   3. Handshake Type is server hello (2)
        //   4. Version is SSL 3.0 (again)
        // -------------------------------------------------
        if((l_resp[0] == 0x16) &&
           (l_resp[1] == 0x03) && (l_resp[2] == 0x00) &&
           (l_resp[5] == 0x02) &&
           (l_resp[9] == 0x03) && (l_resp[10] == 0x00))
        {
                return STATUS_OK;
        }
        return STATUS_ERROR;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_tls(const host_info& a_host_info, protocol_t a_protocol)
{
        int32_t l_s;
        // -------------------------------------------------
        // include server sig for tls versions only
        // -------------------------------------------------
        bool l_include_server_sig = false;
        if((a_protocol == PROTOCOL_TLSv1_3) ||
           (a_protocol == PROTOCOL_TLSv1_2) ||
           (a_protocol == PROTOCOL_TLSv1_1) ||
           (a_protocol == PROTOCOL_TLSv1))
        {
                l_include_server_sig = true;
        }
        UNUSED(g_tlsv12_opt);
        UNUSED(g_tlsv13_opt);
        UNUSED(l_include_server_sig);
        // -------------------------------------------------
        // make tls ext
        // -------------------------------------------------
        vb_t l_tls_ext;
        l_s = vb_gen_tls_ext(l_tls_ext, a_host_info.m_host, l_include_server_sig);
        UNUSED(l_s);
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        switch(a_protocol)
        {
        // -------------------------------------------------
        // PROTOCOL_TLSv1
        // -------------------------------------------------
        case PROTOCOL_TLSv1:
        // fallthru
        // -------------------------------------------------
        // PROTOCOL_TLSv1_1
        // -------------------------------------------------
        case PROTOCOL_TLSv1_1:
        // fallthru
        // -------------------------------------------------
        // PROTOCOL_TLSv1_2
        // -------------------------------------------------
        case PROTOCOL_TLSv1_2:
        {
                // -----------------------------------------
                // ext: support groups
                // -----------------------------------------
                _VB_APPEND_OBJ(l_tls_ext, g_tlsv12_opt);
                break;
        }
        // -------------------------------------------------
        // PROTOCOL_TLSv1_3
        // -------------------------------------------------
        case PROTOCOL_TLSv1_3:
        {
                // -----------------------------------------
                // ext: supported_groups
                // -----------------------------------------
                _VB_APPEND_OBJ(l_tls_ext, g_tlsv13_opt);
                // -----------------------------------------
                // ext: add key shares for X25519.
                // -----------------------------------------
                vb_gen_tls_ext_add_default_key_share(l_tls_ext);
                // -----------------------------------------
                // add supported_versions extension to
                // signify using TLS v1.3.
                // -----------------------------------------
                _VB_APPEND_OBJ(l_tls_ext, g_blk_ext_tlsv13);
                break;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        // -------------------------------------------------
        // update len
        // -------------------------------------------------
        _VB_EXT_UPDATE_LEN(l_tls_ext);
        // -------------------------------------------------
        // generate cipher suites
        // -------------------------------------------------
        vb_t l_cipher_suites;
        l_s = vb_gen_cipher_suites(l_cipher_suites, a_protocol);
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // create client hello
        // -------------------------------------------------
        vb_t l_clnt_hello;
        l_s = vb_gen_client_hello(l_clnt_hello,
                                  a_protocol,
                                  l_cipher_suites,
                                  l_tls_ext);
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("...\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // create a socket to target.
        // -------------------------------------------------
        conn l_conn(a_host_info);
        l_s = l_conn.connect();
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error: performing connect.\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // send client client hello
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, &l_clnt_hello[0], l_clnt_hello.size(), 0);
        if(l_s <= 0)
        {
                NDBG_PRINT("error: send() failed sending client hello: reason[%d]: %s\n", errno, strerror(errno));
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // if not hello message -assume not supported
        // -------------------------------------------------
        uint8_t* l_hello = NULL;
        l_hello = (uint8_t *)malloc(_TLS_RECORD_SIZE*sizeof(uint8_t));
        l_s = get_server_hello(l_hello, l_conn);
        if(l_s != STATUS_OK)
        {
                //NDBG_PRINT("error: performing get_server_hello\n");
                if(l_hello) { free(l_hello); l_hello = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate version high byte
        // -------------------------------------------------
        if(l_hello[9] != 0x03)
        {
                //NDBG_PRINT("l_hello[09]: 0x%0X\n", l_hello[9]);
                if(l_hello) { free(l_hello); l_hello = NULL;}
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // get server's tls version and compare with sent.
        // -------------------------------------------------
        uint8_t l_tls_ver_low_byte = 0;
        switch(a_protocol)
        {
        case PROTOCOL_TLSv1:
        {
                l_tls_ver_low_byte = 1;
                break;
        }
        case PROTOCOL_TLSv1_1:
        {
                l_tls_ver_low_byte = 2;
                break;
        }
        case PROTOCOL_TLSv1_2:
        {
                l_tls_ver_low_byte = 3;
                break;
        }
        case PROTOCOL_TLSv1_3:
        {
                l_tls_ver_low_byte = 3;
                break;
        }
        default:
        {
                l_tls_ver_low_byte = 0;
                break;
        }
        }
        // -------------------------------------------------
        // check
        // -------------------------------------------------
        if(l_hello[10] != l_tls_ver_low_byte)
        {
                //NDBG_PRINT("l_hello[10]: 0x%0X\n", l_hello[10]);
                if(l_hello) { free(l_hello); l_hello = NULL;}
                return STATUS_ERROR;
        }
        if(l_hello) { free(l_hello); l_hello = NULL;}
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_fallback(const host_info& a_host_info, protocol_t a_protocol)
{
#ifdef SSL_MODE_SEND_FALLBACK_SCSV
        bool l_downgraded = true;
        protocol_t l_next_protocol = PROTOCOL_TLSv1_3;
        // -------------------------------------------------
        // get opt
        // -------------------------------------------------
        long l_p_opt;
        l_p_opt = get_protocol_opt_flag(a_protocol);
        if(a_protocol == PROTOCOL_NONE)
        {
                l_downgraded = false;
        }
        // -------------------------------------------------
        // new tls socket
        // -------------------------------------------------
        {
        tls_conn l_tls_conn(a_host_info, l_p_opt);
        // -------------------------------------------------
        // set flags
        // -------------------------------------------------
        l_tls_conn.m_opt_ctx_mode_send_fallback_scsv = true;
        l_tls_conn.m_opt_ssl_legacy_server_connect = true;
        l_tls_conn.m_opt_ssl_no_compression = true;
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                if(l_downgraded)
                {
                        if(SSL_get_error(l_tls_conn.m_ssl, l_tls_conn.m_conn_status))
                        {
                                ERR_get_error();
                                if(SSL_get_error(l_tls_conn.m_ssl, l_tls_conn.m_conn_status))
                                {
                                        printf("    Server %ssupports%s TLS Fallback SCSV\n\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                                        return STATUS_OK;
                                }
                        }
                }
                else
                {
                        printf("    %sConnection failed%s - unable to determine TLS Fallback SCSV support\n\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF);
                        return STATUS_OK;
                }
        }
        // -------------------------------------------------
        // connected successfully
        // -------------------------------------------------
        if(!l_downgraded)
        {
                int l_ssl_version;
                l_ssl_version = SSL_version(l_tls_conn.m_ssl);
                if(l_ssl_version == TLS1_3_VERSION)
                {
                        l_next_protocol = PROTOCOL_TLSv1_2;
                }
                else if(l_ssl_version == TLS1_2_VERSION)
                {
                        l_next_protocol = PROTOCOL_TLSv1_1;
                }
                else if(l_ssl_version == TLS1_VERSION)
                {
                        l_next_protocol = PROTOCOL_TLSv1;
                }
                else if(l_ssl_version == TLS1_VERSION)
                {
                        printf("    Server only supports TLSv1.0");
                        return STATUS_OK;
                }
                else
                {
                        printf("    Server doesn't support TLS - skipping TLS Fallback SCSV check\n\n");
                        return STATUS_OK;
                }
        }
        else
        {
                printf("    Server %sdoes not%s support TLS Fallback SCSV\n\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        }
        // shut down socket...
        }
        // -------------------------------------------------
        // Call function again with downgraded protocol
        // -------------------------------------------------
        if(!l_downgraded)
        {
                check_fallback(a_host_info, l_next_protocol);
        }
#else
        // -------------------------------------------------
        // not supported
        // -------------------------------------------------
        printf("    %sOpenSSL version does not support SCSV fallback%s\n\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
#endif
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_reneg(const host_info& a_host_info)
{
        // -------------------------------------------------
        // new tls socket
        // note seems to require TLSv1.2 and below...
        // -------------------------------------------------
        tls_conn l_tls_conn(a_host_info, PROTOCOL_OP_FLAG_NO_v1_3);
        // -------------------------------------------------
        // set flags
        // -------------------------------------------------
        l_tls_conn.m_opt_ctx_no_session_resumption_on_renegotiation = true;
        l_tls_conn.m_opt_ssl_legacy_server_connect = true;
        //l_tls_conn.m_opt_ssl_allow_unsafe_legacy_renegotiation = true;
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                printf("    Session renegotiation %snot supported%s\n\n",
                       ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                return STATUS_ERROR;
        }
#if( OPENSSL_VERSION_NUMBER > 0x009080cfL )
        // -------------------------------------------------
        // SSL_get_secure_renegotiation_support() appeared
        // first in OpenSSL 0.9.8m
        // -------------------------------------------------
        int l_secure = 0;
        l_secure = SSL_get_secure_renegotiation_support(l_tls_conn.m_ssl);
        if(l_secure)
        {
                printf("    Session renegotiation %ssecure%s %ssupported%s\n\n",
                       ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF,
                       ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                return STATUS_OK;
        }
        // -------------------------------------------------
        // if secure renegotiation server might still
        // support insecure renegotiations
        // -------------------------------------------------
#endif
        // -------------------------------------------------
        // renegotiate connection
        // -------------------------------------------------
        // ???
        //setBlocking(ssl);
        l_s = SSL_renegotiate(l_tls_conn.m_ssl);
        // ???
        UNUSED(l_s);
        // -------------------------------------------------
        // hangs if 'encrypted alert' sent by server
        // send renegotiation request to server
        // TODO :: XXX hanging here
        // -------------------------------------------------
        l_s = SSL_do_handshake(l_tls_conn.m_ssl);
        // ???
        UNUSED(l_s);
        int l_ssl_state = 0;
        l_ssl_state = SSL_get_state(l_tls_conn.m_ssl);
        if(l_ssl_state == TLS_ST_OK)
        {
                // -----------------------------------------
                // send renegotiation rqst to server
                // -----------------------------------------
                int l_res;
                l_res = SSL_do_handshake(l_tls_conn.m_ssl);
                if(l_res != 1)
                {
                        // TODO
                        //printf_error("\n\nSSL_do_handshake() call failed\n");
                }
                l_ssl_state = SSL_get_state(l_tls_conn.m_ssl);
                if(l_ssl_state == TLS_ST_OK)
                {
                        printf("    Session renegotiation %sInsecure%s supported\n\n",
                               ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                        return STATUS_OK;
                }
        }
        printf("    Session renegotiation %snot supported%s\n\n",
               ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_compression(const host_info& a_host_info)
{
        // -------------------------------------------------
        // new tls socket
        // note seems to require TLSv1.2 and below...
        // -------------------------------------------------
        tls_conn l_tls_conn(a_host_info, PROTOCOL_OP_FLAG_NO_v1_3);
        // -------------------------------------------------
        // set flags
        // -------------------------------------------------
        l_tls_conn.m_opt_ctx_no_session_resumption_on_renegotiation = true;
        l_tls_conn.m_opt_ssl_legacy_server_connect = true;
        l_tls_conn.m_opt_ssl_no_compression = true;
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                printf("    Session renegotiation %snot supported%s\n\n",
                       ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // get session/compression methods
        // -------------------------------------------------
        SSL_SESSION *l_session = NULL;
        l_session = SSL_get_session(l_tls_conn.m_ssl);
        if(!l_session)
        {
                return STATUS_ERROR;
        }
#ifndef OPENSSL_NO_COMP
        // Make sure zlib is actually present
        if(sk_SSL_COMP_num(SSL_COMP_get_compression_methods()) != 0)
        {
                uint32_t l_c_id = 0;
                l_c_id = SSL_SESSION_get_compress_id(l_session);
                if(l_c_id == 0)
                {
                        printf("    Compression %sdisabled%s\n\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
                }
                else
                {
                        printf("    Compression %senabled%s (CRIME)\n\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                }
        }
        else
#endif
        {
                printf("    %sOpenSSL version does not support compression%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                printf("    %sRebuild with zlib1g-dev package for zlib support%s\n\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_heartbleed(const host_info& a_host_info, protocol_t a_protocol)
{
        // -------------------------------------------------
        // create a socket to target.
        // -------------------------------------------------
        int32_t l_s;
        conn l_conn(a_host_info);
        l_s = l_conn.connect();
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Credit to Jared Stafford (jspenguin@jspenguin.org)
        // -------------------------------------------------
        uint8_t l_hello[] = {
                0x16,0x03,0x01,0x00,0xdc,0x01,0x00,0x00,0xd8,0x03,0x00,0x53,0x43,0x5b,0x90,0x9d,0x9b,0x72,0x0b,0xbc,0x0c,0xbc,0x2b,0x92,0xa8,0x48,0x97,0xcf,0xbd,0x39,0x04,0xcc,0x16,0x0a,0x85,0x03,0x90,0x9f,0x77,0x04,0x33,0xd4,0xde,0x00,0x00,0x66,0xc0,0x14,0xc0,0x0a,0xc0,0x22,0xc0,0x21,0x00,0x39,0x00,0x38,0x00,0x88,0x00,0x87,0xc0,0x0f,0xc0,0x05,0x00,0x35,0x00,0x84,0xc0,0x12,0xc0,0x08,0xc0,0x1c,0xc0,0x1b,0x00,0x16,0x00,0x13,0xc0,0x0d,0xc0,0x03,0x00,0x0a,0xc0,0x13,0xc0,0x09,0xc0,0x1f,0xc0,0x1e,0x00,0x33,0x00,0x32,0x00,0x9a,0x00,0x99,0x00,0x45,0x00,0x44,0xc0,0x0e,0xc0,0x04,0x00,0x2f,0x00,0x96,0x00,0x41,0xc0,0x11,0xc0,0x07,0xc0,0x0c,0xc0,0x02,0x00,0x05,0x00,0x04,0x00,0x15,0x00,0x12,0x00,0x09,0x00,0x14,0x00,0x11,0x00,0x08,0x00,0x06,0x00,0x03,0x00,0xff,0x01,0x00,0x00,0x49,0x00,0x0b,0x00,0x04,0x03,0x00,0x01,0x02,0x00,0x0a,0x00,0x34,0x00,0x32,0x00,0x0e,0x00,0x0d,0x00,0x19,0x00,0x0b,0x00,0x0c,0x00,0x18,0x00,0x09,0x00,0x0a,0x00,0x16,0x00,0x17,0x00,0x08,0x00,0x06,0x00,0x07,0x00,0x14,0x00,0x15,0x00,0x04,0x00,0x05,0x00,0x12,0x00,0x13,0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x0f,0x00,0x10,0x00,0x11,0x00,0x23,0x00,0x00,0x00,0x0f,0x00,0x01,0x01
        };
        if(a_protocol == PROTOCOL_TLSv1)
        {
                l_hello[10] = 0x01;
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if(a_protocol == PROTOCOL_TLSv1_1)
        {
                l_hello[10] = 0x02;
        }
        else if(a_protocol == PROTOCOL_TLSv1_2)
        {
                l_hello[10] = 0x03;
        }
#endif
        else if(a_protocol == PROTOCOL_TLSv1_3)
        {
                l_hello[10] = 0x03;
        }
        // -------------------------------------------------
        // send hello
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, l_hello, sizeof(l_hello), 0);
        if(l_s <= 0)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // create heartbeat
        // -------------------------------------------------
        char l_hb[8] = {0x18,0x03,0x00,0x00,0x03,0x01,0x40,0x00};
        if(a_protocol == PROTOCOL_TLSv1)
        {
                l_hb[2] = 0x01;
        }
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
        else if(a_protocol == PROTOCOL_TLSv1_1)
        {
                l_hb[2] = 0x02;
        }
        else if(a_protocol == PROTOCOL_TLSv1_2)
        {
                l_hb[2] = 0x03;
        }
#endif
        else if(a_protocol == PROTOCOL_TLSv1_3)
        {
                l_hb[2] = 0x03;
        }
        // -------------------------------------------------
        // send heartbeat
        // -------------------------------------------------
        l_s = send(l_conn.m_fd, l_hb, sizeof(l_hb), 0);
        if(l_s <= 0)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        char l_hb_buf[65536];
        while(1)
        {
                memset(l_hb_buf, 0, sizeof(l_hb_buf));
                // -----------------------------------------
                // Read 5 byte header
                // -----------------------------------------
                int l_r_s = recv(l_conn.m_fd, l_hb_buf, 5, 0);
                if(l_r_s <= 0)
                {
                        break;
                }
                char typ = l_hb_buf[0];
                // -----------------------------------------
                // Combine 2 bytes to get payload length
                // -----------------------------------------
                uint16_t l_ln = l_hb_buf[4] | l_hb_buf[3] << 8;
                // -----------------------------------------
                // Debugging
                // -----------------------------------------
                //uint16_t ver = l_hb_buf[2] | l_hb_buf[1] << 8;
                //printf("%hhX %hhX %hhX %hhX %hhX - %d %d %d\n", l_hb_buf[0], l_hb_buf[1], l_hb_buf[2], l_hb_buf[3], l_hb_buf[4], typ, ver, l_ln);
                memset(l_hb_buf, 0, sizeof(l_hb_buf));
                // -----------------------------------------
                // Read rest of record
                // -----------------------------------------
                l_r_s = recv(l_conn.m_fd, l_hb_buf, l_ln, 0);
                if(l_r_s <= 0)
                {
                        break;
                }
                // -----------------------------------------
                // Server returned error
                // -----------------------------------------
                if(typ == 21)
                {
                        break;
                }
                // -----------------------------------------
                // Successful response
                // -----------------------------------------
                else if(typ == 24 && l_ln > 3)
                {
                        printf("%svulnerable%s to heartbleed\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                        return STATUS_OK;
                }
        }
        printf("%snot vulnerable%s to heartbleed\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: outputs an accepted cipher to console and XML file.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void print_cipher(protocol_t a_protocol,
                         bool a_first,
                         SSL* a_ssl)
{
        // -------------------------------------------------
        // indent
        // -------------------------------------------------
        printf("    ");
        // -------------------------------------------------
        // accepted
        // -------------------------------------------------
        if(a_first)
        {
                printf("%sPreferred%s ", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        }
        else
        {
                printf("Accepted  ");
        }
        // -------------------------------------------------
        // version
        // -------------------------------------------------
        const char *l_protocol_str = NULL;
        l_protocol_str = get_protocol_str(a_protocol);
        if(a_protocol == PROTOCOL_TLSv1)
        {
                printf("%sTLSv1.0%s  ", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF);
        }
        else
        {
                printf("%7s  ", l_protocol_str);
        }
        // -------------------------------------------------
        // bits
        // -------------------------------------------------
        const SSL_CIPHER *l_c = NULL;
        int l_c_bits = -1;
        l_c = SSL_get_current_cipher(a_ssl);
        l_c_bits = SSL_CIPHER_get_bits(l_c, NULL);
        uint32_t l_tmp = 0;
        if(l_c_bits < 10)
        {
                l_tmp = 2;
        }
        else if(l_c_bits < 100)
        {
                l_tmp = 1;
        }
        if(l_c_bits == -1)
        {
                printf("%s??%s bits  ", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF);
        }
        else if(l_c_bits == 0)
        {
                printf("%s%d%s bits  ", ANSI_COLOR_BG_RED, l_c_bits, ANSI_COLOR_OFF);
        }
        else if(l_c_bits >= 112)
        {
                printf("%s%d%s bits  ", ANSI_COLOR_FG_GREEN, l_c_bits, ANSI_COLOR_OFF);
        }
        else if(l_c_bits > 56)
        {
                printf("%s%d%s bits  ", ANSI_COLOR_FG_YELLOW, l_c_bits, ANSI_COLOR_OFF);
        }
        else
        {
                printf("%s%d%s bits  ", ANSI_COLOR_FG_RED, l_c_bits, ANSI_COLOR_OFF);
        }
        while(l_tmp != 0)
        {
                l_tmp--;
                printf(" ");
        }
        // -------------------------------------------------
        // cipher id
        // -------------------------------------------------
#if 0
        if(a_show_cipher_ids)
        {
                uint32_t l_c_id = 0;
                l_c_id = SSL_CIPHER_get_id(l_c);
                l_c_id = l_c_id & 0x00ffffff;
                char l_cipher_id_hex[8] = {0};
                snprintf(l_cipher_id_hex, sizeof(l_cipher_id_hex) - 1, "0x%04X", l_c_id);
                printf("%8s ", l_cipher_id_hex);
        }
#endif
        // -------------------------------------------------
        // cipher name
        // -------------------------------------------------
        const char *l_c_name = NULL;
        l_c_name = SSL_CIPHER_get_name(l_c);
        if(strstr(l_c_name, "NULL"))
        {
                printf("%s%-29s%s", ANSI_COLOR_BG_RED, l_c_name, ANSI_COLOR_OFF);
        }
        else if(strstr(l_c_name, "ADH") || strstr(l_c_name, "AECDH") || strstr(l_c_name, "_anon_"))
        {
                printf("%s%-29s%s", ANSI_COLOR_FG_MAGENTA, l_c_name, ANSI_COLOR_OFF);
        }
        else if(strstr(l_c_name, "EXP"))
        {
                printf("%s%-29s%s", ANSI_COLOR_FG_RED, l_c_name, ANSI_COLOR_OFF);
        }
        else if(strstr(l_c_name, "RC4") || strstr(l_c_name, "DES"))
        {
                printf("%s%-29s%s", ANSI_COLOR_FG_YELLOW, l_c_name, ANSI_COLOR_OFF);
        }
        // =================================================
        // Developed by Chinese government ???
        // =================================================
        else if(strstr(l_c_name, "_SM4_"))
        {
                printf("%s%-29s%s", ANSI_COLOR_FG_YELLOW, l_c_name, ANSI_COLOR_OFF);
        }
        // =================================================
        // Developed by Russian government ???
        // =================================================
        else if(strstr(l_c_name, "_GOSTR341112_"))
        {
                printf("%s%-29s%s", ANSI_COLOR_FG_YELLOW, l_c_name, ANSI_COLOR_OFF);
        }
        else if((strstr(l_c_name, "CHACHA20") || (strstr(l_c_name, "GCM"))) && strstr(l_c_name, "DHE"))
        {
                printf("%s%-29s%s", ANSI_COLOR_FG_GREEN, l_c_name, ANSI_COLOR_OFF);
        }
        else
        {
                printf("%-29s", l_c_name);
        }
        // -------------------------------------------------
        // cipher details
        // -------------------------------------------------
        // TODO flag if???
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && !defined(LIBRESSL_VERSION_NUMBER)
        EVP_PKEY *l_key = NULL;
        if(!SSL_get_server_tmp_key(a_ssl, &l_key))
        {
                printf("\n");
                return;
        }
        switch (EVP_PKEY_id(l_key))
        {
        case EVP_PKEY_RSA:
        {
                if      (EVP_PKEY_bits(l_key) <= 768)  { printf(" RSA %s%d%s bits", ANSI_COLOR_FG_RED,    EVP_PKEY_bits(l_key), ANSI_COLOR_OFF); }
                else if(EVP_PKEY_bits(l_key) <= 1024) { printf(" RSA %s%d%s bits", ANSI_COLOR_FG_YELLOW, EVP_PKEY_bits(l_key), ANSI_COLOR_OFF);}
                else                                   { printf(" RSA %d bits", EVP_PKEY_bits(l_key)); }
                break;
        }
        case EVP_PKEY_DH:
        {
                if      (EVP_PKEY_bits(l_key) <= 768)  { printf(" DHE %s%d%s bits", ANSI_COLOR_FG_RED, EVP_PKEY_bits(l_key), ANSI_COLOR_OFF); }
                else if(EVP_PKEY_bits(l_key) <= 1024) { printf(" DHE %s%d%s bits", ANSI_COLOR_FG_YELLOW, EVP_PKEY_bits(l_key), ANSI_COLOR_OFF); }
                else                                   { printf(" DHE %d bits", EVP_PKEY_bits(l_key)); }
                break;
        }
        case EVP_PKEY_EC:
        {
                EC_KEY *l_ec = EVP_PKEY_get1_EC_KEY(l_key);
                int l_nid;
                const char *l_cname;
                l_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(l_ec));
                EC_KEY_free(l_ec);
                l_cname = EC_curve_nid2nist(l_nid);
                if(!l_cname)
                {
                        l_cname = OBJ_nid2sn(l_nid);
                }
                printf(" Curve %s DHE %d", l_cname, EVP_PKEY_bits(l_key));
                break;
        }
        case EVP_PKEY_X25519:
        {
                printf(" Curve %s25519%s DHE %d", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, EVP_PKEY_bits(l_key));
                break;
        }
        case EVP_PKEY_X448:
        {
                printf(" Curve %s448%s DHE %d", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, EVP_PKEY_bits(l_key));
                break;
        }
        default:
        {
                printf(" %sUnknown ID (%d)%s", ANSI_COLOR_FG_YELLOW, EVP_PKEY_id(l_key), ANSI_COLOR_OFF);
                break;
        }
        }
        if(l_key) { EVP_PKEY_free(l_key); l_key = NULL; }
#endif
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        printf("\n");
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_ciphers(const host_info& a_host_info, protocol_t a_protocol)
{
        // -------------------------------------------------
        // init ciphers list
        // -------------------------------------------------
        std::string l_ciphers_str = _CIPHERSUITE_LIST_ALL;
        // -------------------------------------------------
        // special list for tlsv1.3
        // -------------------------------------------------
        if(a_protocol == PROTOCOL_TLSv1_3)
        {
                l_ciphers_str = _TLSV13_CIPHERSUITES;
        }
        else if(a_protocol == PROTOCOL_TLSv1_2)
        {
                l_ciphers_str = _CIPHERSUITE_LIST_OTHER;
        }
        // -------------------------------------------------
        // get options
        // -------------------------------------------------
        long l_opt;
        l_opt = get_protocol_opt_flag(a_protocol);
        // -------------------------------------------------
        // l_ciphers_list
        // -------------------------------------------------
        typedef std::list<std::string> ciphers_list_t;
        ciphers_list_t l_ciphers_list;
        std::size_t l_pos = 0;
        std::size_t l_prev = 0;
        l_pos = l_ciphers_str.find(":");
        while(l_pos != std::string::npos)
        {
                l_ciphers_list.push_back(l_ciphers_str.substr(l_prev, l_pos - l_prev));
                l_prev = l_pos + 1;
                l_pos = l_ciphers_str.find(":", l_prev);
        }
        l_ciphers_list.push_back(l_ciphers_str.substr(l_prev, l_pos - l_prev));
        // -------------------------------------------------
        // loop until server won't accept more ciphers
        // -------------------------------------------------
        bool l_first = true;
        while(true)
        {
                tls_conn l_tls_conn(a_host_info, l_opt);
                // -----------------------------------------
                // setup
                // -----------------------------------------
                l_tls_conn.m_protocol = a_protocol;
                l_tls_conn.m_opt_ctx_set_min_proto_version = true;
                l_tls_conn.m_opt_ctx_ciphers = l_ciphers_str;
                // -----------------------------------------
                // connect
                // -----------------------------------------
                int32_t l_s;
                l_s = l_tls_conn.connect();
                if(l_s != STATUS_OK)
                {
                        // check conn status for other errors
                        if(l_tls_conn.m_conn_status != 1)
                        {
                                //printf_verbose("SSL_get_error(ssl, cipherStatus) said: %d\n", SSL_get_error(ssl, cipherStatus));
                        }
                        break;
                }
                //NDBG_PRINT("conn_status: %d\n", l_tls_conn.m_conn_status);
                // -----------------------------------------
                // get cipher name
                // -----------------------------------------
                const char *l_cipher = NULL;
                l_cipher = SSL_get_cipher_name(l_tls_conn.m_ssl);
                //NDBG_PRINT("l_cipher:      %s\n", l_cipher);
                //NDBG_PRINT("l_ciphers_str: %s\n", l_ciphers_str.c_str());
                // -----------------------------------------
                // skip cipher
                // TODO -investigate why marked as enabled
                // -----------------------------------------
                if(strcmp(l_cipher, "DES-CBC3-SHA") == 0)
                {
                        break;
                }
                // -----------------------------------------
                // output
                // -----------------------------------------
                print_cipher(a_protocol,
                             l_first,
                             l_tls_conn.m_ssl);
                l_first = false;
                // -----------------------------------------
                // for tlsv1.3 remove from list
                // -----------------------------------------
                if((a_protocol == PROTOCOL_TLSv1_3) ||
                   (a_protocol == PROTOCOL_NONE))
                {
                        // ---------------------------------
                        // done if no more ciphers to test
                        // ---------------------------------
                        if(l_ciphers_list.empty())
                        {
                                break;
                        }
                        // ---------------------------------
                        // remove from list
                        // ---------------------------------
                        std::string l_new_str;
                        for(ciphers_list_t::iterator i_c = l_ciphers_list.begin();
                            i_c != l_ciphers_list.end();)
                        {
                                if(*i_c == l_cipher)
                                {
                                        l_ciphers_list.erase(i_c++);
                                }
                                else
                                {
                                        if(i_c != l_ciphers_list.begin())
                                        {
                                                l_new_str += ":";
                                        }
                                        l_new_str += *i_c;
                                        ++i_c;
                                }
                        }
                        l_ciphers_str = l_new_str;
                }
                // -----------------------------------------
                // append !(not) to list
                // -----------------------------------------
                else
                {
                        l_ciphers_str += ":!";
                        l_ciphers_str += l_cipher;
                }
                //NDBG_PRINT("l_ciphers_str: %s\n", l_ciphers_str.c_str());
        }
        // -------------------------------------------------
        // done if tlsv1.3
        // -------------------------------------------------
#if 0
        if(sslMethod == TLSv1_3_client_method())
        {
                return STATUS_OK;
        }
#endif
        // -------------------------------------------------
        // test missing ciphersuites.
        // -------------------------------------------------
        // TODO ??? -seems broken
#if 0
        int tls_version = TLSv1_0;
        if(sslMethod == TLSv1_1_client_method())
        {
                tls_version = TLSv1_1;
        }
        else if(sslMethod == TLSv1_2_client_method())
        {
                tls_version = TLSv1_2;
        }
        testMissingCiphers(options, tls_version);
#endif
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_sig_algos(const host_info& a_host_info, protocol_t a_protocol)
{
        // -------------------------------------------------
        // type
        // -------------------------------------------------
        typedef struct _sig_algo {
                uint16_t m_sig_id;
                const char *m_sig_name;
                const char *m_color;
        } sig_algo_t;
        // -------------------------------------------------
        // sig algo list
        // -------------------------------------------------
        // ast un-assigned ID
#define BOGUS_SIG_ALG_ID 0xfdff
        static sig_algo_t s_sig_algos[] = {
                // test if server is accepting all.
                {BOGUS_SIG_ALG_ID, "bogus", ANSI_COLOR_FG_RED},
                {0x0001, "rsa_pkcs1_nohash", ANSI_COLOR_FG_RED},
                {0x0002, "dsa_nohash", ANSI_COLOR_FG_RED},
                {0x0003, "ecdsa_nohash", ANSI_COLOR_FG_RED},
                {0x0101, "rsa_pkcs1_md5", ANSI_COLOR_FG_RED},
                {0x0102, "dsa_md5", ANSI_COLOR_FG_RED},
                {0x0103, "ecdsa_md5", ANSI_COLOR_FG_RED},
                {0x0201, "rsa_pkcs1_sha1", ANSI_COLOR_FG_RED},
                {0x0202, "dsa_sha1", ANSI_COLOR_FG_RED},
                {0x0203, "ecdsa_sha1", ANSI_COLOR_FG_RED},
                {0x0301, "rsa_pkcs1_sha224", ANSI_COLOR_FG_YELLOW},
                {0x0302, "dsa_sha224", ANSI_COLOR_FG_RED},
                {0x0303, "ecdsa_sha224", ANSI_COLOR_FG_YELLOW},
                {0x0401, "rsa_pkcs1_sha256", ANSI_COLOR_FG_WHITE},
                {0x0402, "dsa_sha256", ANSI_COLOR_FG_RED},
                {0x0403, "ecdsa_secp256r1_sha256", ANSI_COLOR_FG_WHITE},
                {0x0501, "rsa_pkcs1_sha384", ANSI_COLOR_FG_WHITE},
                {0x0502, "dsa_sha384", ANSI_COLOR_FG_RED},
                {0x0503, "ecdsa_secp384r1_sha384", ANSI_COLOR_FG_WHITE},
                {0x0601, "rsa_pkcs1_sha512", ANSI_COLOR_FG_WHITE},
                {0x0602, "dsa_sha512", ANSI_COLOR_FG_RED},
                {0x0603, "ecdsa_secp521r1_sha512", ANSI_COLOR_FG_WHITE},
                {0x0804, "rsa_pss_rsae_sha256", ANSI_COLOR_FG_WHITE},
                {0x0805, "rsa_pss_rsae_sha384", ANSI_COLOR_FG_WHITE},
                {0x0806, "rsa_pss_rsae_sha512", ANSI_COLOR_FG_WHITE},
                {0x0807, "ed25519", ANSI_COLOR_FG_GREEN},
                {0x0808, "ed448", ANSI_COLOR_FG_GREEN},
                {0x0809, "rsa_pss_pss_sha256", ANSI_COLOR_FG_WHITE},
                {0x080a, "rsa_pss_pss_sha384", ANSI_COLOR_FG_WHITE},
                {0x080b, "rsa_pss_pss_sha512", ANSI_COLOR_FG_WHITE},
        };
        // -------------------------------------------------
        // generate cipher suites
        // -------------------------------------------------
        int32_t l_s;
        vb_t l_cipher_suites;
        l_s = vb_gen_cipher_suites(l_cipher_suites, a_protocol);
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // create resp buffer
        // -------------------------------------------------
        uint8_t* l_hello = NULL;
        l_hello = (uint8_t *)malloc(_TLS_RECORD_SIZE*sizeof(uint8_t));
        // -------------------------------------------------
        // for each signature algorithm...
        // -------------------------------------------------
        uint32_t l_sig_algos_len = ARRAY_SIZE(s_sig_algos);
        for(uint32_t i_sa = 0; i_sa < l_sig_algos_len; ++i_sa)
        {
                //NDBG_PRINT("tls_version: %4d sig_id: %6u name: %s\n", a_protocol, l_sig_algos[i_sa].m_sig_id,  l_sig_algos[i_sa].m_sig_name);
                vb_t l_tls_ext;
                //const char* l_sa_name = l_sig_algos[i_sa].m_sig_name;
                //NDBG_PRINT("test: sig[%u]: %s\n", i_sa, l_sa_name);
                // -----------------------------------------
                // make generic TLS extensions
                // (w/ SNI, accepted EC point formats, etc).
                // -----------------------------------------
                l_s = vb_gen_tls_ext(l_tls_ext, a_host_info.m_host);
                UNUSED(l_s);
                // -----------------------------------------
                // tlsv1.3 specific extensions
                // -----------------------------------------
                if(a_protocol == PROTOCOL_TLSv1_3)
                {
                        // ---------------------------------
                        // extension: supported_groups
                        // ---------------------------------
                        _VB_APPEND_OBJ(l_tls_ext, g_blk_ext_supported_groups);
                        // ---------------------------------
                        // add key shares for X25519.
                        // ---------------------------------
                        vb_gen_tls_ext_add_default_key_share(l_tls_ext);
                        // ---------------------------------
                        // add supported_versions extension to
                        // signify using TLS v1.3.
                        // ---------------------------------
                        _VB_APPEND_OBJ(l_tls_ext, g_blk_ext_tlsv13);
                }
                // -----------------------------------------
                // add signature_algorithms extension.
                // only add one group testing for.
                // -----------------------------------------
                _VB_APPEND_OBJ(l_tls_ext, g_blk_ext_sig_algo);
                _VB_APPEND_UINT16(l_tls_ext, s_sig_algos[i_sa].m_sig_id);
                _VB_EXT_UPDATE_LEN(l_tls_ext);
                // -----------------------------------------
                // create client hello
                // -----------------------------------------
                //NDBG_PRINT("CIPHERSUITE\n");
                //_VB_DISPLAY(l_cipher_suites);
                //NDBG_PRINT("TLS EXT\n");
                //_VB_DISPLAY(l_tls_ext);
                vb_t l_clnt_hello;
                l_s = vb_gen_client_hello(l_clnt_hello,
                                          a_protocol,
                                          l_cipher_suites,
                                          l_tls_ext);
                if(l_s != STATUS_OK)
                {
                        //NDBG_PRINT("...\n");
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // create a socket to target.
                // -----------------------------------------
                conn l_conn(a_host_info);
                l_s = l_conn.connect();
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // send client client hello
                // -----------------------------------------
                //NDBG_PRINT("CLIENT HELLO\n");
                //_VB_DISPLAY(l_clnt_hello);
                l_s = send(l_conn.m_fd, &l_clnt_hello[0], l_clnt_hello.size(), 0);
                if(l_s <= 0)
                {
                        NDBG_PRINT("error: send() failed sending client hello: reason[%d]: %s\n", errno, strerror(errno));
                        return STATUS_ERROR;
                }
                // -------------------------------------------------
                // clear buffer
                // -------------------------------------------------
                memset(l_hello, 0, _TLS_RECORD_SIZE*sizeof(uint8_t));
                // -------------------------------------------------
                // if not hello message -assume not supported
                // -------------------------------------------------
                l_s = get_server_hello(l_hello, l_conn);
                if(l_s != STATUS_OK)
                {
                        continue;
                }
                // -----------------------------------------
                // if server accepted bogus signature ID
                // conclude will accept all of them
                // (and not test any further).
                // some servers do this
                // -----------------------------------------
                if(s_sig_algos[i_sa].m_sig_id == BOGUS_SIG_ALG_ID)
                {
                        //printf("%sServer accepts all signature algorithms.%s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF);
                        //break;
                }
                else
                {
                        printf("    %s %s%s%s\n", get_protocol_str(a_protocol), s_sig_algos[i_sa].m_color, s_sig_algos[i_sa].m_sig_name, ANSI_COLOR_OFF);
                }
        }
        if(l_hello) { free(l_hello); l_hello = NULL;}
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: enumerates all the group key exchanges supported by the server.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_groups(const host_info& a_host_info, protocol_t a_protocol)
{
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        typedef struct _group_key_exchange {
                uint16_t m_id;
                const char *m_name;
                uint32_t m_bit_strength;
                const char *m_color;
                // NID for group, or -1 for X25519/X448.
                int32_t m_nid;
                // One of the NID_TYPE_* flags.
                uint32_t m_nid_type;
                uint16_t m_len;
        } group_key_exchange_t;
        // -------------------------------------------------
        // auto-generated by:
        //   ./tools/iana_tls_supported_groups_parser.py
        // -on December 24, 2019
        // -------------------------------------------------
        // Not Applicable (i.e.: X25519/X448)
        #define _NID_TYPE_NA 0
        // For ECDHE curves (sec*, P-256/384-521)
        #define _NID_TYPE_ECDHE 1
        // For ffdhe*
        #define _NID_TYPE_DHE 2
        // -------------------------------------------------
        // bit strength of DHE 2048 and 3072-bit moduli is
        // taken directly from:
        // NIST SP 800-57 pt.1, rev4., pg. 53;
        // DHE 4096, 6144, and 8192 estimated w/ document.
        // -------------------------------------------------
        static group_key_exchange_t s_gk_x[] =
        {
                {0x0001, "sect163k1", 81, ANSI_COLOR_FG_RED, NID_sect163k1, _NID_TYPE_ECDHE, 0},
                {0x0002, "sect163r1", 81, ANSI_COLOR_FG_RED, NID_sect163r1, _NID_TYPE_ECDHE, 0},
                {0x0003, "sect163r2", 81, ANSI_COLOR_FG_RED, NID_sect163r2, _NID_TYPE_ECDHE, 0},
                {0x0004, "sect193r1", 96, ANSI_COLOR_FG_RED, NID_sect193r1, _NID_TYPE_ECDHE, 0},
                {0x0005, "sect193r2", 96, ANSI_COLOR_FG_RED, NID_sect193r2, _NID_TYPE_ECDHE, 0},
                {0x0006, "sect233k1", 116, ANSI_COLOR_FG_WHITE, NID_sect233k1, _NID_TYPE_ECDHE, 0},
                {0x0007, "sect233r1", 116, ANSI_COLOR_FG_WHITE, NID_sect233r1, _NID_TYPE_ECDHE, 0},
                {0x0008, "sect239k1", 119, ANSI_COLOR_FG_WHITE, NID_sect239k1, _NID_TYPE_ECDHE, 0},
                {0x0009, "sect283k1", 141, ANSI_COLOR_FG_WHITE, NID_sect283k1, _NID_TYPE_ECDHE, 0},
                {0x000a, "sect283r1", 141, ANSI_COLOR_FG_WHITE, NID_sect283r1, _NID_TYPE_ECDHE, 0},
                {0x000b, "sect409k1", 204, ANSI_COLOR_FG_WHITE, NID_sect409k1, _NID_TYPE_ECDHE, 0},
                {0x000c, "sect409r1", 204, ANSI_COLOR_FG_WHITE, NID_sect409r1, _NID_TYPE_ECDHE, 0},
                {0x000d, "sect571k1", 285, ANSI_COLOR_FG_WHITE, NID_sect571k1, _NID_TYPE_ECDHE, 0},
                {0x000e, "sect571r1", 285, ANSI_COLOR_FG_WHITE, NID_sect571r1, _NID_TYPE_ECDHE, 0},
                {0x000f, "secp160k1", 80, ANSI_COLOR_FG_RED, NID_secp160k1, _NID_TYPE_ECDHE, 0},
                {0x0010, "secp160r1", 80, ANSI_COLOR_FG_RED, NID_secp160r1, _NID_TYPE_ECDHE, 0},
                {0x0011, "secp160r2", 80, ANSI_COLOR_FG_RED, NID_secp160r2, _NID_TYPE_ECDHE, 0},
                {0x0012, "secp192k1", 96, ANSI_COLOR_FG_RED, NID_secp192k1, _NID_TYPE_ECDHE, 0},
                {0x0013, "secp192r1", 96, ANSI_COLOR_FG_RED, NID_X9_62_prime192v1, _NID_TYPE_ECDHE, 0},
                {0x0014, "secp224k1", 112, ANSI_COLOR_FG_WHITE, NID_secp224k1, _NID_TYPE_ECDHE, 0},
                {0x0015, "secp224r1", 112, ANSI_COLOR_FG_WHITE, NID_secp224r1, _NID_TYPE_ECDHE, 0},
                {0x0016, "secp256k1", 128, ANSI_COLOR_FG_GREEN, NID_secp256k1, _NID_TYPE_ECDHE, 0},
                {0x0017, "secp256r1 (NIST P-256)", 128, ANSI_COLOR_FG_WHITE, NID_X9_62_prime256v1, _NID_TYPE_ECDHE, 0},
                {0x0018, "secp384r1 (NIST P-384)", 192, ANSI_COLOR_FG_WHITE, NID_secp384r1, _NID_TYPE_ECDHE, 0},
                {0x0019, "secp521r1 (NIST P-521)", 260, ANSI_COLOR_FG_WHITE, NID_secp521r1, _NID_TYPE_ECDHE, 0},
                {0x001a, "brainpoolP256r1", 128, ANSI_COLOR_FG_WHITE, NID_brainpoolP256r1, _NID_TYPE_ECDHE, 0},
                {0x001b, "brainpoolP384r1", 192, ANSI_COLOR_FG_WHITE, NID_brainpoolP384r1, _NID_TYPE_ECDHE, 0},
                {0x001c, "brainpoolP512r1", 256, ANSI_COLOR_FG_WHITE, NID_brainpoolP512r1, _NID_TYPE_ECDHE, 0},
                {0x001d, "x25519", 128, ANSI_COLOR_FG_GREEN, -1, _NID_TYPE_NA, 32},
                {0x001e, "x448", 224, ANSI_COLOR_FG_GREEN, -1, _NID_TYPE_NA, 56},
                {0x0100, "ffdhe2048", 112, ANSI_COLOR_FG_WHITE, NID_ffdhe2048, _NID_TYPE_DHE, 256},
                {0x0101, "ffdhe3072", 128, ANSI_COLOR_FG_WHITE, NID_ffdhe3072, _NID_TYPE_DHE, 384},
                {0x0102, "ffdhe4096", 150, ANSI_COLOR_FG_WHITE, NID_ffdhe4096, _NID_TYPE_DHE, 512},
                {0x0103, "ffdhe6144", 175, ANSI_COLOR_FG_WHITE, NID_ffdhe6144, _NID_TYPE_DHE, 768},
                {0x0104, "ffdhe8192", 192, ANSI_COLOR_FG_WHITE, NID_ffdhe8192, _NID_TYPE_DHE, 1024},
        };
        // -------------------------------------------------
        // cipher suites
        // -------------------------------------------------
        int32_t l_s;
        vb_t l_cipher_suites;
        if(a_protocol == PROTOCOL_TLSv1_3)
        {
                l_s = vb_gen_cipher_suites(l_cipher_suites, a_protocol);
                if(l_s != STATUS_OK)
                {
                        return STATUS_OK;
                }
        }
        // -------------------------------------------------
        // w/ TLSv1.2 (and maybe below), passing all
        // ciphersuites causes false negatives.
        // instead use string of bytes sniffed from a
        // OpenSSL client connection.
        // -------------------------------------------------
        else
        {
                static uint8_t s_ciphers_sniffed[] = {
                        0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24,
                        0xc0, 0x14, 0xc0, 0x0a, 0x00, 0xa5, 0x00, 0xa3,
                        0x00, 0xa1, 0x00, 0x9f, 0x00, 0x6b, 0x00, 0x6a,
                        0x00, 0x69, 0x00, 0x68, 0x00, 0x39, 0x00, 0x38,
                        0x00, 0x37, 0x00, 0x36, 0x00, 0x88, 0x00, 0x87,
                        0x00, 0x86, 0x00, 0x85, 0xc0, 0x32, 0xc0, 0x2e,
                        0xc0, 0x2a, 0xc0, 0x26, 0xc0, 0x0f, 0xc0, 0x05,
                        0x00, 0x9d, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x84,
                        0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x27, 0xc0, 0x23,
                        0xc0, 0x13, 0xc0, 0x09, 0x00, 0xa4, 0x00, 0xa2,
                        0x00, 0xa0, 0x00, 0x9e, 0x00, 0x67, 0x00, 0x40,
                        0x00, 0x3f, 0x00, 0x3e, 0x00, 0x33, 0x00, 0x32,
                        0x00, 0x31, 0x00, 0x30, 0x00, 0x9a, 0x00, 0x99,
                        0x00, 0x98, 0x00, 0x97, 0x00, 0x45, 0x00, 0x44,
                        0x00, 0x43, 0x00, 0x42, 0xc0, 0x31, 0xc0, 0x2d,
                        0xc0, 0x29, 0xc0, 0x25, 0xc0, 0x0e, 0xc0, 0x04,
                        0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x96,
                        0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c,
                        0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0xc0, 0x12,
                        0xc0, 0x08, 0x00, 0x16, 0x00, 0x13, 0x00, 0x10,
                        0x00, 0x0d, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a,
                        0x00, 0xff
                };
                _VB_APPEND_OBJ(l_cipher_suites, s_ciphers_sniffed);
        }
        // -------------------------------------------------
        // create resp buffer
        // -------------------------------------------------
        uint8_t* l_hello = NULL;
        l_hello = (uint8_t *)malloc(_TLS_RECORD_SIZE*sizeof(uint8_t));
        // -------------------------------------------------
        // for each key exchange group...
        // -------------------------------------------------
        uint32_t l_gkx_len = ARRAY_SIZE(s_gk_x);
        for(uint32_t i_k = 0; i_k < l_gkx_len; ++i_k)
        {
                const group_key_exchange_t& l_gk_x = s_gk_x[i_k];
                //NDBG_PRINT("%s group[id: %d]: %s\n", get_protocol_str(a_protocol), l_gk_x.m_nid_type, l_gk_x.m_name);
                uint16_t l_k_x_len = l_gk_x.m_len;
                // -----------------------------------------
                // generate key exchange data.
                // -----------------------------------------
                vb_t l_key_exchange;
                // -----------------------------------------
                // generate "random" data.
                // X25519 and X448 public keys have no
                // discernible structure.
                // -----------------------------------------
                if(l_gk_x.m_nid_type == _NID_TYPE_NA)
                {
                        srand(time(NULL) ^ 0xdeadbeef);
                        for(int j = 0; j < l_gk_x.m_len; ++j)
                        {
                                uint8_t c = (uint8_t)rand();
                                _VB_APPEND_UINT8(l_key_exchange, c);
                        }
                }
                // -----------------------------------------
                // ECDHE
                // -----------------------------------------
                else if(l_gk_x.m_nid_type == _NID_TYPE_ECDHE)
                {
                        // ---------------------------------
                        // generate the ECDHE key.
                        // ---------------------------------
                        EC_KEY *l_key = NULL;
                        l_key = EC_KEY_new_by_curve_name(l_gk_x.m_nid);
                        if((l_key == NULL) ||
                           (EC_KEY_generate_key(l_key) != 1))
                        {
                                if(l_key) {EC_KEY_free(l_key); l_key = NULL;}
                                //fprintf(stderr, "Failed to generate ECDHE key for l_gk_x.m_nid %d\n", l_gk_x.m_nid);
                                continue;
                        }
                        // ---------------------------------
                        // copy key into *new* byte array
                        // ---------------------------------
                        uint8_t *l_kex_buf = NULL;
                        l_k_x_len = EC_KEY_key2buf(l_key, POINT_CONVERSION_UNCOMPRESSED, &l_kex_buf, NULL);
                        if(l_kex_buf == NULL)
                        {
                                if(l_key) {EC_KEY_free(l_key); l_key = NULL;}
                                //fprintf(stderr, "Failed to obtain ECDHE public key bytes.\n");
                                continue;
                        }
                        // ---------------------------------
                        // append
                        // ---------------------------------
                        l_key_exchange.insert(l_key_exchange.end(), l_kex_buf, l_kex_buf+l_k_x_len);
                        if(l_kex_buf) {OPENSSL_free(l_kex_buf); l_kex_buf = NULL;}
                        if(l_key) {EC_KEY_free(l_key); l_key = NULL;}
                }
                // -----------------------------------------
                // DHE
                // -----------------------------------------
                else if(l_gk_x.m_nid_type == _NID_TYPE_DHE)
                {
                        // ---------------------------------
                        // value (Y) for FFDHE group must
                        // be 1 < Y < p - 1 (see RFC7919).
                        // GnuTLS checks
                        //  Y ^ q mod p == 1
                        // (see GnuTLS v3.6.11.1, lib/nettle/pk.c:291).
                        // easiest way to do could be to
                        // generate real DH public keys.
                        // ---------------------------------
                        DH *l_dh = DH_new_by_nid(l_gk_x.m_nid);
                        if(!DH_generate_key(l_dh))
                        {
                                //fprintf(stderr, "Failed to generate DH key for l_gk_x.m_nid %d\n", l_gk_x.m_nid);
                                if(l_dh) {DH_free(l_dh); l_dh = NULL;}
                                continue;
                        }
                        // ---------------------------------
                        // make array to read in DH public key.
                        // ---------------------------------
                        uint32_t l_bytes_len = l_k_x_len;
                        uint8_t *l_bytes = (uint8_t *)calloc(l_bytes_len, sizeof(uint8_t));
                        // ---------------------------------
                        // export public key to array.
                        // ---------------------------------
                        const BIGNUM *pub_key = NULL;
                        DH_get0_key(l_dh, &pub_key, NULL);
                        if(!BN_bn2binpad(pub_key, l_bytes, l_bytes_len))
                        {
                                //fprintf(stderr, "Failed to get DH key for l_gk_x.m_nid %d\n", l_gk_x.m_nid);
                                if(l_bytes) {free(l_bytes); l_bytes = NULL; }
                                if(l_dh) {DH_free(l_dh); l_dh = NULL;}
                                continue;
                        }
                        // ---------------------------------
                        // add the bytes to byte string.
                        // ---------------------------------
                        l_key_exchange.insert(l_key_exchange.end(), l_bytes, l_bytes+l_bytes_len);
                        if(l_bytes) {free(l_bytes); l_bytes = NULL; }
                        if(l_dh) {DH_free(l_dh); l_dh = NULL;}
                }
                // -----------------------------------------
                // unrecognized...
                // -----------------------------------------
                else
                {
                        // Use the provided value, since it must be a specific format.
                        //fprintf(stderr, "Error: unknown NID_TYPE in struct: %d\n", l_gk_x.m_nid_type);
                        if(l_hello) { free(l_hello); l_hello = NULL; }
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // make generic TLS extensions
                // (w/ SNI, accepted EC point formats, etc).
                // -----------------------------------------
                vb_t l_tls_ext;
                l_s = vb_gen_tls_ext(l_tls_ext, a_host_info.m_host, true);
                if(l_s != STATUS_OK)
                {
                        if(l_hello) { free(l_hello); l_hello = NULL; }
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // tlsv1.3 specific extensions
                // -----------------------------------------
                if(a_protocol == PROTOCOL_TLSv1_3)
                {
                        // ---------------------------------
                        // add supported_versions extension to
                        // signify using TLS v1.3.
                        // ---------------------------------
                        _VB_APPEND_OBJ(l_tls_ext, g_blk_ext_tlsv13);
                        _VB_EXT_UPDATE_LEN(l_tls_ext);
                }
                // -----------------------------------------
                // add supported_groups extension.
                // add the one group testing for.
                // -----------------------------------------
                static uint8_t s_ext_groups[] = {
                        0x00, 0x0a, // ext type: supported_groups (10)
                        0x00, 0x04, // ext Length (4)
                        0x00, 0x02, // Supported Groups List Length (2)
                };
                _VB_APPEND_OBJ(l_tls_ext, s_ext_groups);
                _VB_APPEND_UINT16(l_tls_ext, l_gk_x.m_id);
                // -----------------------------------------
                // add the key_share extension if TLS v1.3
                // for current group type
                // -----------------------------------------
                if(a_protocol == PROTOCOL_TLSv1_3)
                {
                        uint16_t l_kx_len = (uint16_t)(l_key_exchange.size());
                        static uint8_t s_ext_type_ks[] = {
                                0x00, 0x33, // ext type: key_share (51)
                        };
                        _VB_APPEND_OBJ(l_tls_ext, s_ext_type_ks);  // ext type: key_share (51)
                        _VB_APPEND_UINT16(l_tls_ext, l_kx_len+6);  // ext length
                        _VB_APPEND_UINT16(l_tls_ext, l_kx_len+4);  // client key share length
                        _VB_APPEND_UINT16(l_tls_ext, l_gk_x.m_id); // group id
                        _VB_APPEND_UINT16(l_tls_ext, l_kx_len);    // key exchange length
                        _VB_APPEND_VB(l_tls_ext, l_key_exchange);  // key exchange
                }
                // -----------------------------------------
                // update TLS extensions length since
                // manually added.
                // -----------------------------------------
                _VB_EXT_UPDATE_LEN(l_tls_ext);
                // -----------------------------------------
                // create client hello
                // -----------------------------------------
                //NDBG_PRINT("CIPHERSUITE\n");
                //_VB_DISPLAY(l_cipher_suites);
                //NDBG_PRINT("TLS EXT\n");
                //_VB_DISPLAY(l_tls_ext);
                vb_t l_clnt_hello;
                l_s = vb_gen_client_hello(l_clnt_hello,
                                          a_protocol,
                                          l_cipher_suites,
                                          l_tls_ext);
                if(l_s != STATUS_OK)
                {
                        //NDBG_PRINT("...\n");
                        if(l_hello) { free(l_hello); l_hello = NULL; }
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // create a socket to target.
                // -----------------------------------------
                conn l_conn(a_host_info);
                l_s = l_conn.connect();
                if(l_s != STATUS_OK)
                {
                        if(l_hello) { free(l_hello); l_hello = NULL; }
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // send client client hello
                // -----------------------------------------
                //NDBG_PRINT("CLIENT HELLO\n");
                //_VB_DISPLAY(l_clnt_hello);
                l_s = send(l_conn.m_fd, &l_clnt_hello[0], l_clnt_hello.size(), 0);
                if(l_s <= 0)
                {
                        //NDBG_PRINT("error: send() failed sending client hello: reason[%d]: %s\n", errno, strerror(errno));
                        return STATUS_ERROR;
                }
                // -------------------------------------------------
                // clear buffer
                // -------------------------------------------------
                memset(l_hello, 0, _TLS_RECORD_SIZE*sizeof(uint8_t));
                // -------------------------------------------------
                // if not hello message -assume not supported
                // -------------------------------------------------
                l_s = get_server_hello(l_hello, l_conn);
                if(l_s != STATUS_OK)
                {
                        continue;
                }
                // -----------------------------------------
                // for TLSv1.2 and below, examine server key
                // exchange record.
                // -----------------------------------------
                if(a_protocol < PROTOCOL_TLSv1_3)
                {
                        uint8_t* l_r = NULL;
                        l_r = (uint8_t *)malloc(_TLS_RECORD_SIZE*sizeof(uint8_t));
                        l_s = get_tls_handshake_record(l_r, l_conn);
                        if(l_s != STATUS_OK)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // server hello done
                        // check handshake type byte[5]
                        // ---------------------------------
                        if(l_r[5] == 14)
                        {
                                if(l_r) { free(l_r); l_r = NULL; }
                                continue;
                        }
                        // ---------------------------------
                        // skip non-server key exchange
                        // records (type 12)
                        // ---------------------------------
                        bool l_done = false;
                        while((l_s != STATUS_ERROR) &&
                              (l_r[5] != 12))
                        {
                                l_s = get_tls_handshake_record(l_r, l_conn);
                                if(l_s != STATUS_OK)
                                {
                                        if(l_r) { free(l_r); l_r = NULL; }
                                        l_done = true;
                                        break;
                                }
                                // -------------------------
                                // check for done
                                // -------------------------
                                if(l_r[5] == 14)
                                {
                                        if(l_r) { free(l_r); l_r = NULL; }
                                        l_done = true;
                                        //NDBG_PRINT("...\n");
                                        break;
                                }
                        }
                        // ---------------------------------
                        // error skip this group.
                        // ---------------------------------
                        if(l_done ||
                           (l_s == STATUS_ERROR))
                        {
                                if(l_r) { free(l_r); l_r = NULL; }
                                continue;
                        }
                        // ---------------------------------
                        // if server key exchange does not
                        // have named_curve (3) field,
                        // skip group.
                        // ---------------------------------
                        if(l_r[9] != 0x03)
                        {
                                if(l_r) { free(l_r); l_r = NULL; }
                                continue;
                        }
                        // ---------------------------------
                        // check named_curve result is group
                        // requested.
                        // ---------------------------------
                        uint16_t l_svr_group_id;
                        l_svr_group_id = l_r[10] << 8 | l_r[11];
                        if(l_svr_group_id != l_gk_x.m_id)
                        {
                                if(l_r) { free(l_r); l_r = NULL; }
                                continue;
                        }
                        // ---------------------------------
                        // okay...
                        // ---------------------------------
                        if(l_r) { free(l_r); l_r = NULL; }
                }
                // -----------------------------------------
                // results
                // -----------------------------------------
                const char *l_bc = ANSI_COLOR_FG_WHITE;
                if(l_gk_x.m_bit_strength < 112)
                {
                        l_bc = ANSI_COLOR_FG_RED;
                }
                else
                {
                        l_bc = ANSI_COLOR_FG_GREEN;
                }
                printf("    %s  %s%d%s bits  %s%s%s\n",
                        get_protocol_str(a_protocol),
                        l_bc, l_gk_x.m_bit_strength, ANSI_COLOR_OFF,
                        l_gk_x.m_color, l_gk_x.m_name, ANSI_COLOR_OFF);
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        if(l_hello) { free(l_hello); l_hello = NULL; }
        return STATUS_OK;
}
}
