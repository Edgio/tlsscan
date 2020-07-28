//: ----------------------------------------------------------------------------
//: Copyright Verizon.
//:
//: \file:    scan.cc
//: \details: TODO
//:
//: Licensed under the terms of the Apache 2.0 open source license.
//: Please refer to the LICENSE file in the project root for the terms.
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "def.h"
#include "ndebug.h"
#include "scan.h"
#include "cert.h"
#include "protocol.h"
#include <openssl/ssl.h>
#include <string>
#include <list>
//: ----------------------------------------------------------------------------
//: defines...
//: ----------------------------------------------------------------------------
// TODO
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
// TODO
namespace ns_tlsscan {
//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::list<std::string> cipher_list_t;
//: ----------------------------------------------------------------------------
//: \details Callback set w/ SSL_set_security_callback() and
//:                   SSL_CTX_set_security_callback().
//:                   Allows all weak algorithms.
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: \details: populate client ciphers
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t populate_client_ciphers(long a_tls_options, cipher_list_t& ao_cipher_list)
{
        int32_t l_ret = STATUS_OK;
        SSL_CTX* l_ctx = NULL;
        SSL* l_ssl = NULL;
        STACK_OF(SSL_CIPHER) *l_cipher_list;
        // -------------------------------------------------
        // create ctx
        // -------------------------------------------------
        const SSL_METHOD *l_method;
        l_method = TLS_client_method();
        if(!l_method)
        {
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        l_ctx = SSL_CTX_new(l_method);
        if(!l_ctx)
        {
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        SSL_CTX_set_security_level(l_ctx, 0);
        SSL_CTX_set_security_callback(l_ctx, security_callback_allow_all);
        long l_unused;
        l_unused = SSL_CTX_set_options(l_ctx, a_tls_options);
        UNUSED(l_unused);
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
#define _CIPHERSUITE_LIST_ALL "ALL:COMPLEMENTOFALL"
        SSL_CTX_set_cipher_list(l_ctx, _CIPHERSUITE_LIST_ALL);
        l_ssl = SSL_new(l_ctx);
        if(!l_ssl)
        {
                return STATUS_ERROR;
        }
        SSL_set_security_level(l_ssl, 0);
        SSL_set_security_callback(l_ssl, security_callback_allow_all);
        if(l_ssl == NULL)
        {
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        l_cipher_list = SSL_get_ciphers(l_ssl);
        for(int i_c = 0; i_c < sk_SSL_CIPHER_num(l_cipher_list); ++i_c)
        {
                // -----------------------------------------
                // add more???
                // -----------------------------------------
                //sslCipherPointer->sslMethod = sslMethod;
                //sslCipherPointer->version = SSL_CIPHER_get_version(sk_SSL_CIPHER_value(l_cipher_list, i_c));
                //SSL_CIPHER_description(sk_SSL_CIPHER_value(l_cipher_list, i_c), sslCipherPointer->description, sizeof(sslCipherPointer->description) - 1);
                //sslCipherPointer->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(l_cipher_list, i_c), &tempInt);
                std::string l_cipher;
                l_cipher = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(l_cipher_list, i_c));
                if(!l_cipher.empty())
                {
                        ao_cipher_list.push_back(l_cipher);
                }
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
cleanup:
        if(l_ssl) { SSL_free(l_ssl); l_ssl = NULL; }
        if(l_ctx) { SSL_CTX_free(l_ctx); l_ctx = NULL; }
        return l_ret;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t scan_host(const host_info& a_host_info,
                  const scan_opt_t& a_scan_opt)
{
        // -------------------------------------------------
        // banner
        // -------------------------------------------------
        printf("Testing SSL server %s%s%s on port %s%d%s using SNI name %s%s%s\n\n",
                ANSI_COLOR_FG_GREEN, a_host_info.m_host.c_str(), ANSI_COLOR_OFF,
                ANSI_COLOR_FG_GREEN, a_scan_opt.m_port, ANSI_COLOR_OFF,
                ANSI_COLOR_FG_GREEN, a_host_info.m_host.c_str(), ANSI_COLOR_OFF);
        // -------------------------------------------------
        // check protocols
        // -------------------------------------------------
        // TODO add flag???
        typedef std::list<protocol_t> protocol_list_t;
        protocol_list_t l_protocol_list;
        if(1)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sSSL/TLS Protocols:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                l_s = check_tls(a_host_info, PROTOCOL_TLSv1_3);
                if(l_s == STATUS_OK) { printf("    TLSv1.3 is %senabled%s\n",     ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF); l_protocol_list.push_back(PROTOCOL_TLSv1_3);}
                else                 { printf("    TLSv1.3 is %snot enabled%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF); }
                l_s = check_tls(a_host_info, PROTOCOL_TLSv1_2);
                if(l_s == STATUS_OK) { printf("    TLSv1.2 is %senabled%s\n",     ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF); l_protocol_list.push_back(PROTOCOL_TLSv1_2);}
                else                 { printf("    TLSv1.2 is %snot enabled%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF); }
                l_s = check_tls(a_host_info, PROTOCOL_TLSv1_1);
                if(l_s == STATUS_OK) { printf("    TLSv1.1 is %senabled%s\n",     ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF); l_protocol_list.push_back(PROTOCOL_TLSv1_1);}
                else                 { printf("    TLSv1.1 is %snot enabled%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF); }
                l_s = check_tls(a_host_info, PROTOCOL_TLSv1);
                if(l_s == STATUS_OK) { printf("    TLSv1   is %senabled%s\n",     ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF); l_protocol_list.push_back(PROTOCOL_TLSv1);}
                else                 { printf("    TLSv1   is %snot enabled%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF); }
                l_s = check_sslv3(a_host_info);
                if(l_s == STATUS_OK) { printf("    SSLv3   is %senabled%s\n",     ANSI_COLOR_FG_RED, ANSI_COLOR_OFF); l_protocol_list.push_back(PROTOCOL_SSLv3);}
                else                 { printf("    SSLv3   is %snot enabled%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF); }
                l_s = check_sslv2(a_host_info);
                if(l_s == STATUS_OK) { printf("    SSLv2   is %senabled%s\n",    ANSI_COLOR_FG_RED, ANSI_COLOR_OFF); l_protocol_list.push_back(PROTOCOL_SSLv2);}
                else                 { printf("    SSLv2   is %snot enabled%s\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);}
                printf("\n");
        }
        // -------------------------------------------------
        // show client ciphers...
        // -------------------------------------------------
        if(a_scan_opt.m_show_client_ciphers)
        {
                int32_t l_s = STATUS_OK;
                cipher_list_t l_cipher_list;
                l_s = populate_client_ciphers(a_scan_opt.m_tls_options, l_cipher_list);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
                printf("\n  %sOpenSSL-Supported Client Cipher(s):%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                for(cipher_list_t::const_iterator i_c = l_cipher_list.begin();
                    i_c != l_cipher_list.end();
                    ++i_c)
                {
                        printf("    %s\n",i_c->c_str());
                }
                printf("\n");
        }
        // -------------------------------------------------
        // test fallback
        // -------------------------------------------------
        if(a_scan_opt.m_check_fallback)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sTLS Fallback SCSV:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                l_s = check_fallback(a_host_info, PROTOCOL_NONE);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // test renegotiation
        // -------------------------------------------------
        if(a_scan_opt.m_check_reneg)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sTLS renegotiation:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                l_s = check_reneg(a_host_info);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        if(a_scan_opt.m_check_compression)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sTLS Compression:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                l_s = check_compression(a_host_info);
                if(l_s != STATUS_OK)
                {
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // check ciphers
        // -------------------------------------------------
        if(a_scan_opt.m_check_heartbleed)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sHeartbleed:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
                printf("    TLS 1.3 is ");
                l_s = check_heartbleed(a_host_info, PROTOCOL_TLSv1_3);
                printf("    TLS 1.2 is ");
                l_s = check_heartbleed(a_host_info, PROTOCOL_TLSv1_2);
                printf("    TLS 1.1 is ");
                l_s = check_heartbleed(a_host_info, PROTOCOL_TLSv1_1);
#endif
                printf("    TLS 1.0 is ");
                l_s = check_heartbleed(a_host_info, PROTOCOL_TLSv1);
                printf("\n");
                UNUSED(l_s);
        }
        // -------------------------------------------------
        // Print OCSP response
        // -------------------------------------------------
#if OPENSSL_VERSION_NUMBER > 0x00908000L && !defined(OPENSSL_NO_TLSEXT)
        if(a_scan_opt.m_check_ocsp_response)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sOCSP Stapling Request:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                l_s = check_ocsp_request(a_host_info, a_scan_opt.m_tls_options);
                if(l_s != STATUS_OK)
                {
                        // TODO ???
                }
                UNUSED(l_s);
        }
#endif
        // -------------------------------------------------
        // check ciphers
        // -------------------------------------------------
        if(a_scan_opt.m_check_ciphers)
        {
                int32_t l_s = STATUS_OK;
                printf("  %sSupported Server Cipher(s):%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                // -----------------------------------------
                // TLSv1_3_client_method
                // -----------------------------------------
                l_s = check_ciphers(a_host_info, PROTOCOL_TLSv1_3);
                if(l_s == STATUS_OK)
                {
                        // TODO ???
                }
                // -----------------------------------------
                // TLSv1_2_client_method
                // -----------------------------------------
                l_s = check_ciphers(a_host_info, PROTOCOL_TLSv1_2);
                if(l_s == STATUS_OK)
                {
                        // TODO ???
                }
                // -----------------------------------------
                // TLSv1_1_client_method
                // -----------------------------------------
                l_s = check_ciphers(a_host_info, PROTOCOL_TLSv1_1);
                if(l_s == STATUS_OK)
                {
                        // TODO ???
                }
                // -----------------------------------------
                // TLSv1_client_method
                // -----------------------------------------
                l_s = check_ciphers(a_host_info, PROTOCOL_TLSv1);
                if(l_s == STATUS_OK)
                {
                        // TODO ???
                }
                // -----------------------------------------
                // SSLv3_client_method
                // -----------------------------------------
                l_s = check_ciphers(a_host_info, PROTOCOL_SSLv3);
                if(l_s == STATUS_OK)
                {
                        // TODO ???
                }
                UNUSED(l_s);
                printf("\n");
        }
        // -------------------------------------------------
        // Enumerate key exchange groups.
        // -------------------------------------------------
        if(a_scan_opt.m_check_groups)
        {
                printf("  %sServer Key Exchange Group(s):%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                int32_t l_s;
                uint32_t l_num = 0;
                for(protocol_list_t::iterator i_p = l_protocol_list.begin();
                    i_p != l_protocol_list.end();
                    ++i_p)
                {
                        //NDBG_PRINT("check: %s\n", get_protocol_str(*i_p));
                        l_s = check_groups(a_host_info, *i_p);
                        if(l_s == STATUS_OK)
                        {
                                // TODO ???
                        }
                        // ---------------------------------
                        // break after 2 protocols???
                        // ---------------------------------
                        ++l_num;
                        if(l_num >= 2)
                        {
                                break;
                        }
                }
                UNUSED(l_s);
                printf("\n");
        }
        // -------------------------------------------------
        // Enumerate signature algorithms.
        // -------------------------------------------------
        if(a_scan_opt.m_check_sig_algo)
        {
                printf("  %sServer Signature Algorithm(s):%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
                int32_t l_s;
                uint32_t l_num = 0;
                for(protocol_list_t::iterator i_p = l_protocol_list.begin();
                    i_p != l_protocol_list.end();
                    ++i_p)
                {
                        //NDBG_PRINT("check: %s\n", get_protocol_str(*i_p));
                        l_s = check_sig_algos(a_host_info, *i_p);
                        if(l_s == STATUS_OK)
                        {
                                // TODO ???
                        }
                        // ---------------------------------
                        // break after 2 protocols???
                        // ---------------------------------
                        ++l_num;
                        if(l_num >= 2)
                        {
                                break;
                        }
                }
                UNUSED(l_s);
                printf("\n");
        }
        // -------------------------------------------------
        // Print certificate
        // -------------------------------------------------
        if(a_scan_opt.m_show_cert)
        {
                int32_t l_s;
                l_s = show_cert(a_host_info, a_scan_opt.m_tls_options);
                if(l_s != STATUS_OK)
                {
                        // TODO
                }
        }
        // -------------------------------------------------
        // show weak certificate signing algorithm or
        // key strength
        // -------------------------------------------------
        if(a_scan_opt.m_check_cert)
        {
                int32_t l_s;
                // -----------------------------------------
                // TLSv1_3_client_method
                // -----------------------------------------
                l_s = check_cert_protocol(a_host_info, PROTOCOL_OP_FLAG_TLSv1_3);
                if(l_s == STATUS_OK)
                {
                        goto show_trust_ca;
                }
                //printf("error: connecting with TLSv1.3 -trying TLSv1.2\n");
                // -----------------------------------------
                // TLSv1_2_client_method
                // -----------------------------------------
                l_s = check_cert_protocol(a_host_info, PROTOCOL_OP_FLAG_TLSv1_2);
                if(l_s == STATUS_OK)
                {
                        goto show_trust_ca;
                }
                //printf("error: connecting with TLSv1.2 -trying TLSv1.1\n");
                // -----------------------------------------
                // TLSv1_1_client_method
                // -----------------------------------------
                l_s = check_cert_protocol(a_host_info, PROTOCOL_OP_FLAG_TLSv1_1);
                if(l_s == STATUS_OK)
                {
                        goto show_trust_ca;
                }
                //printf("error: connecting with TLSv1.1 -trying TLSv1\n");
                // -----------------------------------------
                // TLSv1_client_method
                // -----------------------------------------
                l_s = check_cert_protocol(a_host_info, PROTOCOL_OP_FLAG_TLSv1);
                if(l_s == STATUS_OK)
                {
                        goto show_trust_ca;
                }
                //printf("error: certificate information cannot be enumerated through SSLv2 nor SSLv3.\n\n");
        }
        // -------------------------------------------------
        // show client auth trusted CAs
        // -------------------------------------------------
show_trust_ca:
        if(a_scan_opt.m_show_trust_ca)
        {
                int32_t l_s;
                l_s = show_trust_ca(a_host_info, a_scan_opt.m_tls_options);
                if(l_s != STATUS_OK)
                {
                        // TODO
                }
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        return STATUS_OK;
}
}
