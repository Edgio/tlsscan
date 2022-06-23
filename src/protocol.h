//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    protocol.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _TLSSCAN_PROTOCOL_H_
#define _TLSSCAN_PROTOCOL_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <openssl/ssl.h>
#include "host_info.h"
#include "def.h"
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define PROTOCOL_OP_FLAG_SSLv2   (SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)
#define PROTOCOL_OP_FLAG_SSLv3   (SSL_OP_NO_SSLv2|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)
#define PROTOCOL_OP_FLAG_TLSv1   (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)
#define PROTOCOL_OP_FLAG_TLSv1_1 (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)
#define PROTOCOL_OP_FLAG_TLSv1_2 (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_3)
#define PROTOCOL_OP_FLAG_TLSv1_3 (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2)
#define PROTOCOL_OP_FLAG_ALL     (SSL_OP_NO_SSLv2)
#define PROTOCOL_OP_FLAG_NO_v1_3 (SSL_OP_NO_TLSv1_3)
//! ----------------------------------------------------------------------------
//! protocol -> string mapping
//! ----------------------------------------------------------------------------
#define PROTOCOL_MAP(_XX) \
        _XX(0,  NONE,    NONE) \
        _XX(1,  SSLv2,   SSLv2) \
        _XX(2,  SSLv3,   SSLv3) \
        _XX(3,  TLSv1,   TLSv1) \
        _XX(4,  TLSv1_1, TLSv1.1) \
        _XX(5,  TLSv1_2, TLSv1.2) \
        _XX(6,  TLSv1_3, TLSv1.3)

typedef enum _protocol
{
#define _XX(num, name, string) PROTOCOL_##name = num,
        PROTOCOL_MAP(_XX)
#undef _XX
} protocol_t;
//! ----------------------------------------------------------------------------
//! checks
//! ----------------------------------------------------------------------------
int32_t check_sslv2(const host_info& a_host_info);
int32_t check_sslv3(const host_info& a_host_info);
int32_t check_tls(const host_info& a_host_info, protocol_t a_protocol);
int32_t check_fallback(const host_info& a_host_info, protocol_t a_protocol);
int32_t check_reneg(const host_info& a_host_info);
int32_t check_compression(const host_info& a_host_info);
int32_t check_heartbleed(const host_info& a_host_info, protocol_t a_protocol);
int32_t check_ciphers(const host_info& a_host_info, protocol_t a_protocol);
int32_t check_sig_algos(const host_info& a_host_info, protocol_t a_protocol);
int32_t check_groups(const host_info& a_host_info, protocol_t a_protocol);
//! ----------------------------------------------------------------------------
//! util
//! ----------------------------------------------------------------------------
const char* get_protocol_str(protocol_t a_m);
long get_protocol_opt_flag(protocol_t a_protocol);
}
#endif
