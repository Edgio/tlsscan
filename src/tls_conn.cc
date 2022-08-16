//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    tls_conn.cc
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <string>
#include <map>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_conn.h"
#include "ndebug.h"
#include "def.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef CIPHERSUITE_LIST_ALL
#define CIPHERSUITE_LIST_ALL "ALL:COMPLEMENTOFALL"
#endif
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! \details Callback set w/ SSL_set_security_callback() and
//!                   SSL_CTX_set_security_callback().
//!                   Allows all weak algorithms.
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int security_callback_allow_all(const SSL *s,
                                       const SSL_CTX *ctx,
                                       int op,
                                       int bits,
                                       int nid,
                                       void *other,
                                       void *ex)
{
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
typedef std::map <std::string, long>tls_options_map_t;
tls_options_map_t g_tls_options_map;
int32_t get_tls_options_str_val(const std::string& a_options_str, long &ao_val)
{
        std::string l_options_str = a_options_str;
        if(g_tls_options_map.empty())
        {
                g_tls_options_map["SSL_OP_NO_SSLv2"] = SSL_OP_NO_SSLv2;
                g_tls_options_map["SSL_OP_NO_SSLv3"] = SSL_OP_NO_SSLv3;
                g_tls_options_map["SSL_OP_NO_TLSv1"] = SSL_OP_NO_TLSv1;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
                g_tls_options_map["SSL_OP_NO_TLSv1_3"] = SSL_OP_NO_TLSv1_3;
#endif
                g_tls_options_map["SSL_OP_NO_TLSv1_2"] = SSL_OP_NO_TLSv1_2;
                g_tls_options_map["SSL_OP_NO_TLSv1_1"] = SSL_OP_NO_TLSv1_1;
        }
        // Remove whitespace
        l_options_str.erase( std::remove_if( l_options_str.begin(), l_options_str.end(), ::isspace ), l_options_str.end() );
        ao_val = 0;
        std::string l_token;
        std::string l_delim = "|";
        size_t l_start = 0U;
        size_t l_end = l_options_str.find(l_delim);
        while(l_end != std::string::npos)
        {
                l_token = l_options_str.substr(l_start, l_end - l_start);
                l_start = l_end + l_delim.length();
                l_end = l_options_str.find(l_delim, l_start);
                //NDBG_PRINT("TOKEN: %s\n", l_token.c_str());
                tls_options_map_t::iterator i_option  = g_tls_options_map.find(l_token);
                if(i_option == g_tls_options_map.end())
                {
                        //TRC_ERROR("unrecognized ssl option: %s\n", l_token.c_str());
                        return STATUS_ERROR;
                }
                ao_val |= i_option->second;
        };
        l_token = l_options_str.substr(l_start, l_options_str.length() - l_start);
        //NDBG_PRINT("TOKEN: %s\n", l_token.c_str());
        tls_options_map_t::iterator i_option  = g_tls_options_map.find(l_token);
        if(i_option == g_tls_options_map.end())
        {
                //TRC_ERROR("unrecognized ssl option: %s\n", l_token.c_str());
                return STATUS_ERROR;
        }
        ao_val |= i_option->second;
        //NDBG_PRINT("ao_val: 0x%08lX\n", ao_val);
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
tls_conn::tls_conn(const host_info& a_host_info,
                   long a_tls_options,
                   SSL_CTX* a_ctx):
        conn(a_host_info),
        m_protocol(PROTOCOL_NONE),
        m_tls_options(a_tls_options),
        m_ctx(a_ctx),
        m_ssl(NULL),
        m_bio(NULL),
        m_sni_name(),
        m_opt_ctx_set_min_proto_version(false),
        m_opt_ctx_ciphers(),
        m_opt_ctx_no_session_resumption_on_renegotiation(false),
        m_opt_ctx_mode_send_fallback_scsv(false),
        m_opt_ctx_ocsp_cb(NULL),
        m_opt_ssl_legacy_server_connect(false),
        m_opt_ssl_no_compression(false),
        m_opt_ssl_allow_unsafe_legacy_renegotiation(false),
        m_conn_status(0),
        m_ctx_ext_flag(false)
{
        // -------------------------------------------------
        // mark if supplied
        // -------------------------------------------------
        if(m_ctx)
        {
                m_ctx_ext_flag = true;
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
tls_conn::~tls_conn(void)
{
        cleanup();
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t tls_conn::connect(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // connect...
        // -------------------------------------------------
        l_s = conn::connect();
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error: ...\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // create ctx
        // -------------------------------------------------
        if(!m_ctx_ext_flag)
        {
        if(m_ctx)
        {
                SSL_CTX_free(m_ctx);
                m_ctx = NULL;
        }
        const SSL_METHOD *l_method;
        l_method = TLS_client_method();
        if(!l_method)
        {
                NDBG_PRINT("error: ...\n");
                return STATUS_ERROR;
        }
        m_ctx = SSL_CTX_new(l_method);
        if(!m_ctx)
        {
                NDBG_PRINT("error: ...\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // security level
        // -------------------------------------------------
        SSL_CTX_set_security_level(m_ctx, 0);
        SSL_CTX_set_security_callback(m_ctx, security_callback_allow_all);
#if 0
        // -------------------------------------------------
        // clear options
        // -------------------------------------------------
        if(m_opt_ctx_clear_options)
        {
                SSL_CTX_set_options(m_ctx, 0);
        }
#endif
        // -------------------------------------------------
        // set options
        // -------------------------------------------------
        long l_unused;
        l_unused = SSL_CTX_set_options(m_ctx, m_tls_options);
        UNUSED(l_unused);
        // -------------------------------------------------
        // minimal protocol version
        // -------------------------------------------------
        if(m_opt_ctx_set_min_proto_version &&
           (m_protocol == PROTOCOL_TLSv1_3))
        {
                SSL_CTX_set_min_proto_version(m_ctx, TLS1_3_VERSION);
        }
        // -------------------------------------------------
        // setup ciphers
        // -------------------------------------------------
        if(!m_opt_ctx_ciphers.empty())
        {
                if(m_protocol == PROTOCOL_TLSv1_3)
                {
                        SSL_CTX_set_ciphersuites(m_ctx, m_opt_ctx_ciphers.c_str());
                }
                else
                {
                        SSL_CTX_set_cipher_list(m_ctx, m_opt_ctx_ciphers.c_str());
                }
        }
        // -------------------------------------------------
        // set cipher list all
        // -------------------------------------------------
        else
        {
                l_s = SSL_CTX_set_cipher_list(m_ctx, CIPHERSUITE_LIST_ALL);
                if (l_s == 0)
                {
                        NDBG_PRINT("error: ...\n");
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // renegotiation
        // -------------------------------------------------
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
        if(m_opt_ctx_no_session_resumption_on_renegotiation)
        {
                unsigned long l_ul_unused;
                l_ul_unused = SSL_CTX_set_options(m_ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
                UNUSED(l_ul_unused);
        }
#endif
        // -------------------------------------------------
        // fallback
        // -------------------------------------------------
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
        if(m_opt_ctx_mode_send_fallback_scsv)
        {
                SSL_CTX_set_mode(m_ctx, SSL_MODE_SEND_FALLBACK_SCSV);
        }
#endif
        }
        // -------------------------------------------------
        // load certs
        // -------------------------------------------------
#if 0
        if((options->clientCertsFile != 0) ||
           (options->privateKeyFile != 0))
        {
                status = loadCerts(options);
        }
#endif
        // -------------------------------------------------
        // Create SSL object...
        // -------------------------------------------------
        if(m_ssl)
        {
                SSL_free(m_ssl);
                m_ssl = NULL;
        }
        m_ssl = SSL_new(m_ctx);
        if(!m_ssl)
        {
                NDBG_PRINT("error: ...\n");
                return STATUS_ERROR;
        }
        SSL_set_security_level(m_ssl, 0);
        SSL_set_security_callback(m_ssl, security_callback_allow_all);
        // -------------------------------------------------
        // Make sure we can connect to insecure servers
        // OpenSSL is going to change the default at a later date
        // -------------------------------------------------
#if(OPENSSL_VERSION_NUMBER > 0x009080cfL)
        if(m_opt_ssl_legacy_server_connect)
        {
                SSL_set_options(m_ssl, SSL_OP_LEGACY_SERVER_CONNECT);
        }
#endif
        // -------------------------------------------------
        // set no compression
        // -------------------------------------------------
#ifdef SSL_OP_NO_COMPRESSION
        if(m_opt_ssl_no_compression)
        {
                SSL_clear_options(m_ssl, SSL_OP_NO_COMPRESSION);
        }
#endif
        // -------------------------------------------------
        // allow unsafe legacy renegotiation
        // -------------------------------------------------
        if(m_opt_ssl_allow_unsafe_legacy_renegotiation)
        {
                SSL_set_options(m_ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
        }
        // -------------------------------------------------
        // set ocsp cb
        // -------------------------------------------------
        if(m_opt_ctx_ocsp_cb)
        {
                SSL_set_tlsext_status_type(m_ssl, TLSEXT_STATUSTYPE_ocsp);
                SSL_CTX_set_tlsext_status_cb(m_ctx, m_opt_ctx_ocsp_cb);
        }
        // -------------------------------------------------
        // Connect socket and BIO
        // -------------------------------------------------
        m_bio = BIO_new_socket(m_fd, BIO_NOCLOSE);
        if(!m_bio)
        {
                NDBG_PRINT("error: ...\n");
                return STATUS_ERROR;
        }
        SSL_set_bio(m_ssl, m_bio, m_bio);
        // -------------------------------------------------
        // set sni
        // -------------------------------------------------
#if (OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT))
        if(!m_host_info.m_host.empty())
        {
                SSL_set_tlsext_host_name(m_ssl, m_host_info.m_host.c_str());
        }
#endif
        // -------------------------------------------------
        // Connect SSL over socket
        // -------------------------------------------------
        m_conn_status = SSL_connect(m_ssl);
        if(m_conn_status != 1)
        {
#if 0
                int l_err;
                l_err = SSL_get_error(m_ssl, m_conn_status);
                if(l_err == SSL_ERROR_SSL)
                {
                        unsigned long l_last_err = ERR_get_error();
                        char *l_buf = NULL;
                        l_buf = ERR_error_string(l_last_err, l_buf);
                        NDBG_PRINT("error: reason: %s\n", l_buf);
                }
                NDBG_PRINT("error: reason: [%d]: %d\n", m_conn_status, l_err);
#endif
                return STATUS_ERROR;
        }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t tls_conn::cleanup(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // Disconnect SSL over socket
        // -------------------------------------------------
        if(m_ssl)
        {
                SSL_shutdown(m_ssl);
        }
        // -------------------------------------------------
        // Free SSL object
        // -------------------------------------------------
        if(m_ssl)
        {
                SSL_free(m_ssl);
                m_ssl = NULL;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(!m_ctx_ext_flag)
        {
        if(m_ctx)
        {
                SSL_CTX_free(m_ctx);
                m_ctx = NULL;
        }
        }
        // -------------------------------------------------
        // parent cleanup...
        // -------------------------------------------------
        l_s = conn::cleanup();
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        return STATUS_OK;
}
}
