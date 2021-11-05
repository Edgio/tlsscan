//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    cert.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _TLSSCAN_CERT_H_
#define _TLSSCAN_CERT_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <openssl/ssl.h>
#include "host_info.h"
namespace ns_tlsscan {
int32_t show_cert(const host_info& a_host_info, long a_tls_options);
int32_t show_trust_ca(const host_info& a_host_info, long a_tls_options);
int32_t check_cert_protocol(const host_info& a_host_info, long a_tls_options);
int32_t check_ocsp_request(const host_info& a_host_info, long a_tls_options);
}
#endif
