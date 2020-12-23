//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    scan.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _TLSSCAN_SCAN_H_
#define _TLSSCAN_SCAN_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <openssl/ssl.h>
#include "host_info.h"
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
typedef struct scan_opt
{
        // -------------------------------------------------
        //
        // -------------------------------------------------
        scan_opt():
                m_check_ciphers(true),
                m_check_groups(false),
                m_check_sig_algo(false),
                m_check_cert(true),
                m_check_fallback(true),
                m_check_reneg(true),
                m_check_compression(false),
                m_check_heartbleed(false),
                m_check_ocsp_response(false),
                m_show_cert(false),
                m_show_trust_ca(false),
                m_show_client_ciphers(false),
                m_port(443),
                m_tls_options()
        {
                m_tls_options = SSL_OP_ALL;
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        bool m_check_ciphers;
        bool m_check_groups;
        bool m_check_sig_algo;
        bool m_check_cert;
        bool m_check_fallback;
        bool m_check_reneg;
        bool m_check_compression;
        bool m_check_heartbleed;
        bool m_check_ocsp_response;
        bool m_show_cert;
        bool m_show_trust_ca;
        bool m_show_client_ciphers;
        uint16_t m_port;
        long m_tls_options;
private:
        // -------------------------------------------------
        //
        // -------------------------------------------------
        scan_opt(const scan_opt&);
        scan_opt& operator=(const scan_opt&);
} scan_opt_t;
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
int32_t scan_host(const host_info& a_host_info, const scan_opt_t& a_scan_opt);
}
#endif
