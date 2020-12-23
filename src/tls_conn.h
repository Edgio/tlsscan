//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    tls_conn.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _TLS_CONN_H_
#define _TLS_CONN_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <stdint.h>
#include "host_info.h"
#include "conn.h"
#include "protocol.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;
namespace ns_tlsscan {
typedef int (*tls_ext_cb_t)(SSL *, void *);
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class tls_conn: public conn
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        tls_conn(const host_info& a_host_info,
                 long a_tls_options = 0,
                 SSL_CTX* a_ctx = NULL);
        ~tls_conn(void);
        int32_t connect(void);
        int32_t cleanup(void);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        protocol_t m_protocol;
        long m_tls_options;
        // SSL state
        SSL_CTX* m_ctx;
        SSL* m_ssl;
        BIO* m_bio;
        std::string m_sni_name;
        bool m_opt_ctx_set_min_proto_version;
        std::string m_opt_ctx_ciphers;
        bool m_opt_ctx_no_session_resumption_on_renegotiation;
        bool m_opt_ctx_mode_send_fallback_scsv;
        tls_ext_cb_t m_opt_ctx_ocsp_cb;
        bool m_opt_ssl_legacy_server_connect;
        bool m_opt_ssl_no_compression;
        bool m_opt_ssl_allow_unsafe_legacy_renegotiation;
        int m_conn_status;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        tls_conn(const tls_conn&);
        tls_conn& operator=(const tls_conn&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_ctx_ext_flag;
};
//! ----------------------------------------------------------------------------
//! util
//! ----------------------------------------------------------------------------
int32_t get_tls_options_str_val(const std::string& a_options_str, long &ao_val);
}
#endif
