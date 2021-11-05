//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    cert.cc
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string.h>
#include "cert.h"
#include "def.h"
#include "tls_conn.h"
#include "ndebug.h"
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
// hacked in include
#include <crypto/ocsp/ocsp_local.h>
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! \details: print out the full certificate
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t show_cert(const host_info& a_host_info, long a_tls_options)
{
        int32_t l_ret = STATUS_OK;
        BIO *l_bio_stdout = NULL;
        X509 *l_x509 = NULL;
        // -------------------------------------------------
        // connect...
        // -------------------------------------------------
        int32_t l_s;
        tls_conn l_tls_conn(a_host_info, a_tls_options);
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                //NDBG_PRINT("error. reason: performing tls connect\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // Setup BIO's
        // -------------------------------------------------
        l_bio_stdout = BIO_new(BIO_s_file());
        if(!l_bio_stdout)
        {
                //NDBG_PRINT("error. reason: TODO\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        BIO_set_fp(l_bio_stdout, stdout, BIO_NOCLOSE);
        // -------------------------------------------------
        // Get Certificate...
        // -------------------------------------------------
        printf("  %sSSL Certificate:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
        l_x509 = SSL_get_peer_certificate(l_tls_conn.m_ssl);
        if(!l_x509)
        {
                //NDBG_PRINT("error. reason: TODO\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // Print a base64 blob version of the cert
        // -------------------------------------------------
        printf("    Certificate blob:\n");
        PEM_write_bio_X509(l_bio_stdout, l_x509);
        //SSL_set_verify(l_tls_conn.m_ssl, SSL_VERIFY_NONE|SSL_VERIFY_CLIENT_ONCE, NULL);
        //X509_print_ex(l_stdout_bp, l_x509, 0, 0);
#define _X509_SUPPORTS(_str) (!(X509_FLAG_COMPAT & _str))
        // -------------------------------------------------
        // Cert Version
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_VERSION)
        {
                long l_t;
                l_t = X509_get_version(l_x509);
                printf("    Version:              %lu\n", l_t);
        }
        // -------------------------------------------------
        // Cert Serial No.
        // adapted from OpenSSL's crypto/asn1/t_x509.c
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_SERIAL)
        {
                ASN1_INTEGER *bs = NULL;
                BIO *l_stdout_bp = NULL;
                BIO *l_xml_bp = NULL;
                l_stdout_bp = BIO_new_fp(stdout, BIO_NOCLOSE);
                long l;
                int i;
                const char *neg = NULL;
                bs=X509_get_serialNumber(l_x509);
                if(BIO_write(l_stdout_bp,"    Serial Number:       ",25) <= 0)
                {
                        return(1);
                }
                if(bs->length <= 4)
                {
                        l=ASN1_INTEGER_get(bs);
                        if(l < 0)
                        {
                                l= -l;
                                neg="-";
                        }
                        else
                        {
                                neg="";
                        }
                        if(BIO_printf(l_stdout_bp," %s%lu (%s0x%lx)\n",neg,l,neg,l) <= 0)
                        {
                                return(1);
                        }
                }
                else
                {
                        neg=(bs->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
                        if(BIO_printf(l_stdout_bp,"%1s%s","",neg) <= 0)
                        {
                                return(1);
                        }
                        for (i=0; i<bs->length; i++)
                        {
                                if(BIO_printf(l_stdout_bp,"%02x%c",bs->data[i], ((i+1 == bs->length)?'\n':':')) <= 0)
                                {
                                        return(1);
                                }
                        }
                }
                if(NULL != l_stdout_bp)
                {
                        BIO_free(l_stdout_bp);
                }
                UNUSED(l_xml_bp);
        }
        // -------------------------------------------------
        // Signature Algo...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_SIGNAME)
        {
                X509_signature_print(l_bio_stdout, X509_get0_tbs_sigalg(l_x509), NULL);
                //printf("    Signature Algorithm: ");
                //i2a_ASN1_OBJECT(l_bio_stdout, X509_get0_tbs_sigalg(l_x509));
                //printf("\n");
        }
        // -------------------------------------------------
        // SSL Certificate Issuer...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_ISSUER)
        {
                char l_buf[1024];
                X509_NAME_oneline(X509_get_issuer_name(l_x509), l_buf, sizeof(l_buf) - 1);
                printf("    Issuer:               %s\n", l_buf);
        }
        // -------------------------------------------------
        // Validity...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_VALIDITY)
        {
                printf("    Not valid before:     ");
                ASN1_TIME_print(l_bio_stdout, X509_get_notBefore(l_x509));
                printf("\n");
                printf("    Not valid after:      ");
                ASN1_TIME_print(l_bio_stdout, X509_get_notAfter(l_x509));
                printf("\n");
        }
        // -------------------------------------------------
        // SSL Certificate Subject...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_SUBJECT)
        {
                char l_buf[1024];
                X509_NAME_oneline(X509_get_subject_name(l_x509), l_buf, sizeof(l_buf) - 1);
                printf("    Subject:              %s\n", l_buf);
        }
        // -------------------------------------------------
        // Public Key Algo...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_PUBKEY)
        {
                EVP_PKEY *l_pk = NULL;
                printf("    Public Key Algorithm: ");
                ASN1_OBJECT *xpoid = NULL;
                i2a_ASN1_OBJECT(l_bio_stdout, xpoid);
                printf("\n");
                // Public Key...
                l_pk = X509_get_pubkey(l_x509);
                if(l_pk == NULL)
                {
                        printf("    Public Key: Could not load\n");
                }
                else
                {
                        switch (EVP_PKEY_id(l_pk))
                        {
                        case EVP_PKEY_RSA:
                                if(EVP_PKEY_get1_RSA(l_pk)!=NULL)
                                {
                                        printf("    RSA Public Key: (%d bit)\n", EVP_PKEY_bits(l_pk));
                                        RSA_print(l_bio_stdout, EVP_PKEY_get1_RSA(l_pk), 6);
                                }
                                else
                                {
                                        printf("    RSA Public Key: NULL\n");
                                }
                                break;
                        case EVP_PKEY_DSA:
                                if(EVP_PKEY_get1_DSA(l_pk)!=NULL)
                                {
                                        printf("    DSA Public Key:\n");
                                        DSA_print(l_bio_stdout, EVP_PKEY_get1_DSA(l_pk), 6);
                                }
                                else
                                {
                                        printf("    DSA Public Key: NULL\n");
                                }
                                break;
                        case EVP_PKEY_EC:
                                if(EVP_PKEY_get1_EC_KEY(l_pk)!=NULL)
                                {
                                        printf("    EC Public Key:\n");
                                        EC_KEY_print(l_bio_stdout, EVP_PKEY_get1_EC_KEY(l_pk), 6);
                                }
                                else
                                {
                                        printf("    EC Public Key: NULL\n");
                                }
                                break;
                        default:
                                printf("    Public Key: Unknown\n");
                                break;
                        }
                        EVP_PKEY_free(l_pk);
                }
        }
        // -------------------------------------------------
        // X509 v3...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_EXTENSIONS)
        {
                if(sk_X509_EXTENSION_num(X509_get0_extensions(l_x509)) > 0)
                {
                        printf("    X509v3 Extensions:\n");
                        int i_ext = 0;
                        for (i_ext = 0; i_ext < sk_X509_EXTENSION_num(X509_get0_extensions(l_x509)); i_ext++)
                        {
                                ASN1_OBJECT *l_asn1 = NULL;
                                X509_EXTENSION *l_ext = NULL;
                                // Get Extension...
                                l_ext = sk_X509_EXTENSION_value(X509_get0_extensions(l_x509), i_ext);
                                // Print Extension name...
                                printf("      ");
                                l_asn1 = X509_EXTENSION_get_object(l_ext);
                                i2a_ASN1_OBJECT(l_bio_stdout, l_asn1);
                                int i_ext_crit;
                                i_ext_crit = X509_EXTENSION_get_critical(l_ext);
                                BIO_printf(l_bio_stdout, ": %s\n", i_ext_crit ? "critical" : "");
                                // Print Extension value...
                                if(!X509V3_EXT_print(l_bio_stdout, l_ext, X509_FLAG_COMPAT, 8))
                                {
                                        printf("        ");
                                        ASN1_STRING_print(l_bio_stdout, X509_EXTENSION_get_data(l_ext));
                                }
                                printf("\n");
                        }
                }
        }
        // -------------------------------------------------
        // Verify Certificate...
        // -------------------------------------------------
        printf("  Verify Certificate:\n");
        long l_verify_s;
        l_verify_s = SSL_get_verify_result(l_tls_conn.m_ssl);
        if(l_verify_s == X509_V_OK)
        {
                printf("    Certificate passed verification\n");
        }
        else
        {
                printf("    %s\n", X509_verify_cert_error_string(l_verify_s));
        }
cleanup:
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_x509)
        {
                X509_free(l_x509);
                l_x509 = NULL;
        }
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_bio_stdout)
        {
                BIO_free(l_bio_stdout);
                l_bio_stdout = NULL;
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details: print out the list of trusted CAs
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t show_trust_ca(const host_info& a_host_info, long a_tls_options)
{
        int32_t l_ret = STATUS_OK;
        BIO *l_bio_stdout = NULL;
        X509 *l_x509 = NULL;
        int i_x_name = 0;
        STACK_OF(X509_NAME) *l_client_ca_list_ptr;
        // -------------------------------------------------
        // connect...
        // -------------------------------------------------
        int32_t l_s;
        tls_conn l_tls_conn(a_host_info, a_tls_options);
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                //NDBG_PRINT("error. reason: performing tls connect\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // Setup BIO's
        // -------------------------------------------------
        l_bio_stdout = BIO_new(BIO_s_file());
        if(!l_bio_stdout)
        {
                //NDBG_PRINT("error. reason: TODO\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        BIO_set_fp(l_bio_stdout, stdout, BIO_NOCLOSE);
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        printf("\n  %sAcceptable client certificate CA names:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
        l_client_ca_list_ptr=SSL_get_client_CA_list(l_tls_conn.m_ssl);
        if((l_client_ca_list_ptr != NULL) && (sk_X509_NAME_num(l_client_ca_list_ptr) > 0))
        {
                for (i_x_name=0; i_x_name<sk_X509_NAME_num(l_client_ca_list_ptr); ++i_x_name)
                {
                        char l_buf[1024];
                        char *l_c = NULL;
                        X509_NAME *l_xn = NULL;
                        l_xn=sk_X509_NAME_value(l_client_ca_list_ptr,i_x_name);
                        l_c = X509_NAME_oneline(l_xn,l_buf,sizeof(l_buf));
                        UNUSED(l_c);
                        printf("%s", l_buf);
                        printf("\n");
                }
        }
        else
        {
                printf("%sNone defined (any)%s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF);
        }
cleanup:
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_x509)
        {
                X509_free(l_x509);
                l_x509 = NULL;
        }
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_bio_stdout)
        {
                BIO_free(l_bio_stdout);
                l_bio_stdout = NULL;
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_cert_protocol(const host_info& a_host_info, long a_tls_options)
{
        int32_t l_ret = STATUS_OK;
        BIO *l_bio_stdout = NULL;
        X509 *l_x509 = NULL;
        // -------------------------------------------------
        // connect...
        // -------------------------------------------------
        int32_t l_s;
        tls_conn l_tls_conn(a_host_info, a_tls_options);
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                //NDBG_PRINT("error. reason: performing tls connect\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        // -------------------------------------------------
        // Setup BIO's
        // -------------------------------------------------
        l_bio_stdout = BIO_new(BIO_s_file());
        if(!l_bio_stdout)
        {
                //NDBG_PRINT("error. reason: TODO\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        BIO_set_fp(l_bio_stdout, stdout, BIO_NOCLOSE);
        // -------------------------------------------------
        // Get Certificate...
        // -------------------------------------------------
        printf("\n  %sSSL Certificate:%s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF);
        l_x509 = SSL_get_peer_certificate(l_tls_conn.m_ssl);
        if(l_x509 == NULL)
        {
                //printf("    Unable to parse certificate\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Cert Serial No.
        // adapted from OpenSSL's crypto/asn1/t_x509.c
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_SERIAL)
        {
                ASN1_INTEGER *bs = NULL;
                BIO *l_stdout_bp = NULL;
                BIO *l_xml_bp = NULL;
                l_stdout_bp = BIO_new_fp(stdout, BIO_NOCLOSE);
                long l;
                int i;
                const char *neg = NULL;
                bs=X509_get_serialNumber(l_x509);
                if(BIO_write(l_stdout_bp,"    Serial Number:       ",25) <= 0)
                {
                        return(1);
                }
                if(bs->length <= 4)
                {
                        l=ASN1_INTEGER_get(bs);
                        if(l < 0)
                        {
                                l= -l;
                                neg="-";
                        }
                        else
                        {
                                neg="";
                        }
                        if(BIO_printf(l_stdout_bp," %s%lu (%s0x%lx)\n",neg,l,neg,l) <= 0)
                        {
                                return(1);
                        }
                }
                else
                {
                        neg=(bs->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
                        if(BIO_printf(l_stdout_bp,"%1s%s","",neg) <= 0)
                        {
                                return(1);
                        }
                        for (i=0; i<bs->length; i++)
                        {
                                if(BIO_printf(l_stdout_bp,"%02x%c",bs->data[i], ((i+1 == bs->length)?'\n':':')) <= 0)
                                {
                                        return(1);
                                }
                        }
                }
                if(NULL != l_stdout_bp)
                {
                        BIO_free(l_stdout_bp);
                }
                UNUSED(l_xml_bp);
        }
        // -------------------------------------------------
        // Signature Algo...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_SIGNAME)
        {
                char certAlgorithm[80];
                const X509_ALGOR *palg = NULL;
                const ASN1_OBJECT *paobj = NULL;
                printf("    Signature Algorithm:  ");
                X509_get0_signature(NULL, &palg, l_x509);
                X509_ALGOR_get0(&paobj, NULL, NULL, palg);
                OBJ_obj2txt(certAlgorithm, sizeof(certAlgorithm), paobj, 0);
                strtok(certAlgorithm, "\n");
                if(strstr(certAlgorithm, "md5") || strstr(certAlgorithm, "sha1"))
                {
                        printf("%s%s%s\n", ANSI_COLOR_FG_RED, certAlgorithm, ANSI_COLOR_OFF);
                }
                else if(strstr(certAlgorithm, "sha512") || strstr(certAlgorithm, "sha256"))
                {
                        printf("%s%s%s\n", ANSI_COLOR_FG_GREEN, certAlgorithm, ANSI_COLOR_OFF);
                }
                else
                {
                        printf("%s\n", certAlgorithm);
                }
                //X509_signature_print(fileBIO, palg, NULL);
        }
        // -------------------------------------------------
        // Public Key...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_PUBKEY)
        {
                EVP_PKEY *l_pk = NULL;
                l_pk = X509_get_pubkey(l_x509);
                if(l_pk == NULL)
                {
                        printf("Public Key: Could not load\n");
                        goto get_issuer;
                }
                int keyBits;
                keyBits=EVP_PKEY_bits(l_pk);
                switch (EVP_PKEY_id(l_pk))
                {
                case EVP_PKEY_RSA:
                        if(EVP_PKEY_get1_RSA(l_pk)!=NULL)
                        {
                                if(keyBits < 2048 )
                                {
                                        printf("    RSA Key Strength:     %s%d%s\n", ANSI_COLOR_FG_RED, keyBits, ANSI_COLOR_OFF);
                                }
                                else if(keyBits >= 4096 )
                                {
                                        printf("    RSA Key Strength:     %s%d%s\n", ANSI_COLOR_FG_GREEN, keyBits, ANSI_COLOR_OFF);
                                }
                                else
                                {
                                        printf("    RSA Key Strength:     %d\n", keyBits);
                                }
                        }
                        else
                        {
                                printf("    RSA Public Key: NULL\n");
                        }
                        printf("\n");
                        break;
                case EVP_PKEY_DSA:
                        if(EVP_PKEY_get1_DSA(l_pk)!=NULL)
                        {
                                // TODO - display key strength
                                // DSA_print(l_bio_stdout, l_pk->pkey.dsa, 6);
                        }
                        else
                        {
                                printf("    DSA Public Key: NULL\n");
                        }
                        break;
                case EVP_PKEY_EC:
                        if(EVP_PKEY_get1_EC_KEY(l_pk))
                        {
                                // TODO - display key strength
                                // EC_KEY_print(l_bio_stdout, l_pk->pkey.ec, 6);
                        }
                        else
                        {
                                printf("    EC Public Key: NULL\n");
                        }
                        break;
                default:
                        printf("    Public Key: Unknown\n");
                        break;
                }
                EVP_PKEY_free(l_pk);
        }
get_issuer:
        // -------------------------------------------------
        // SSL Certificate Issuer...
        // -------------------------------------------------
        if _X509_SUPPORTS(X509_FLAG_NO_ISSUER)
        {
                int cnindex;
                X509_NAME *subj;
                X509_NAME_ENTRY *e;
                ASN1_STRING *d;
                const char *subject;
                const char *issuer;
                // -----------------------------------------
                // Get SSL cert CN
                // -----------------------------------------
                cnindex = -1;
                subj = X509_get_subject_name(l_x509);
                cnindex = X509_NAME_get_index_by_NID(subj, NID_commonName, cnindex);
                // -----------------------------------------
                // SSL cert doesn't have a CN, so just print whole thing
                // -----------------------------------------
                if(cnindex == -1)
                {
                        subject = (char *) X509_NAME_oneline(X509_get_subject_name(l_x509), NULL, 0);
                        printf("    Subject:              %s\n", subject);
                }
                else
                {
                        e = X509_NAME_get_entry(subj, cnindex);
                        d = X509_NAME_ENTRY_get_data(e);
                        subject = (char *) ASN1_STRING_data(d);
                        printf("    Subject:              %s\n", subject);
                }
                // -----------------------------------------
                // Get certificate altnames if supported
                // -----------------------------------------
                if(!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
                {
                        if(sk_X509_EXTENSION_num(X509_get0_extensions(l_x509)) > 0)
                        {
                                cnindex = X509_get_ext_by_NID (l_x509, NID_subject_alt_name, -1);
                                if(cnindex != -1)
                                {
                                        X509_EXTENSION *l_ext = NULL;
                                        l_ext = X509v3_get_ext(X509_get0_extensions(l_x509),cnindex);
                                        printf("    Altnames:             ");
                                        if(!X509V3_EXT_print(l_bio_stdout, l_ext, X509_FLAG_COMPAT, 0))
                                        {
                                                ASN1_STRING_print(l_bio_stdout, X509_EXTENSION_get_data(l_ext));
                                        }
                                        printf("\n");
                                }
                        }
                }
                // -----------------------------------------
                // Get SSL cert issuer
                // -----------------------------------------
                cnindex = -1;
                subj = X509_get_issuer_name(l_x509);
                cnindex = X509_NAME_get_index_by_NID(subj, NID_commonName, cnindex);
                // -----------------------------------------
                // Issuer cert doesn't have a CN, so just print whole thing
                // -----------------------------------------
                if(cnindex == -1)
                {
                        char *issuer = X509_NAME_oneline(X509_get_issuer_name(l_x509), NULL, 0);
                        printf("    Issuer:               %s", issuer);
                }
                else
                {
                        e = X509_NAME_get_entry(subj, cnindex);
                        d = X509_NAME_ENTRY_get_data(e);
                        issuer = (char *) ASN1_STRING_data(d);
                        // If issuer is same as hostname we scanned or is *, flag as self-signed
                        if(
                                        strcmp(issuer, a_host_info.m_host.c_str()) == 0
                                        || strcmp(issuer, subject) == 0
                                        || strcmp(issuer, "*") == 0
                        )
                        {
                                printf("    Issuer:               %s%s%s\n", ANSI_COLOR_FG_RED, issuer, ANSI_COLOR_OFF);
                        }
                        else
                        {
                                printf("    Issuer:               %s\n", issuer);
                        }
                }
        }
        // -------------------------------------------------
        // Check for certificate expiration
        // -------------------------------------------------
        time_t *ptime;
        int timediff;
        ptime = NULL;
        printf("    Not valid before:     ");
        timediff = X509_cmp_time(X509_get_notBefore(l_x509), ptime);
        // -------------------------------------------------
        // Certificate isn't valid yet
        // -------------------------------------------------
        if(timediff > 0)
        {
                printf("%s", ANSI_COLOR_FG_RED);
        }
        else
        {
                printf("%s", ANSI_COLOR_FG_GREEN);
        }
        ASN1_TIME_print(l_bio_stdout, X509_get_notBefore(l_x509));
        printf("%s", ANSI_COLOR_OFF);
        printf("\n");
        printf("    Not valid after:      ");
        timediff = X509_cmp_time(X509_get_notAfter(l_x509), ptime);
        // -------------------------------------------------
        // Certificate has expired
        // -------------------------------------------------
        if(timediff < 0)
        {
                printf("%s", ANSI_COLOR_FG_RED);
        }
        else
        {
                printf("%s", ANSI_COLOR_FG_GREEN);
        }
        ASN1_TIME_print(l_bio_stdout, X509_get_notAfter(l_x509));
        printf("%s", ANSI_COLOR_OFF);
        printf("\n");
cleanup:
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_x509)
        {
                X509_free(l_x509);
                l_x509 = NULL;
        }
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_bio_stdout)
        {
                BIO_free(l_bio_stdout);
                l_bio_stdout = NULL;
        }
        return l_ret;
}
//! ----------------------------------------------------------------------------
//! \details: load client certificates/private keys...
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
int loadCerts(struct tls_check_opt *options)
{
        // Variables...
        int status = 1;
        PKCS12 *pk12 = NULL;
        FILE *pk12File = NULL;
        X509 *cert = NULL;
        EVP_PKEY *pkey = NULL;
        STACK_OF(X509) *ca = NULL;

        // Configure PKey password...
        if(options->privateKeyPassword != 0)
        {
                SSL_CTX_set_default_passwd_cb_userdata(options->ctx, (void *)options->privateKeyPassword);
                SSL_CTX_set_default_passwd_cb(options->ctx, password_callback);
        }

        // Separate Certs and PKey Files...
        if((options->clientCertsFile != 0) && (options->privateKeyFile != 0))
        {
                // Load Cert...
                if(!SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_PEM))
                {
                        if(!SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_ASN1))
                        {
                                if(!SSL_CTX_use_certificate_chain_file(options->ctx, options->clientCertsFile))
                                {
                                        printf("%s    Could not configure certificate(s).%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                                        status = 0;
                                }
                        }
                }

                // Load PKey...
                if(status != 0)
                {
                        if(!SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM))
                        {
                                if(!SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1))
                                {
                                        // Why would the more specific functions succeed if the generic functions failed?
                                        // -- I'm guessing that the original author was hopeful? - io
                                        if(!SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM))
                                        {
                                                if(!SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1))
                                                {
                                                        printf("%s    Could not configure private key.%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                                                        status = 0;
                                                }
                                        }
                                }
                        }
                }
        }

        // PKCS Cert and PKey File...
        else if(options->privateKeyFile != 0)
        {
                pk12File = fopen(options->privateKeyFile, "rb");
                if(pk12File != NULL)
                {
                        pk12 = d2i_PKCS12_fp(pk12File, NULL);
                        if(!pk12)
                        {
                                status = 0;
                                printf("%s    Could not read PKCS#12 file.%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                        }
                        else
                        {
                                if(!PKCS12_parse(pk12, options->privateKeyPassword, &pkey, &cert, &ca))
                                {
                                        status = 0;
                                        printf("%s    Error parsing PKCS#12. Are you sure that password was correct?%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                                }
                                else
                                {
                                        if(!SSL_CTX_use_certificate(options->ctx, cert))
                                        {
                                                status = 0;
                                                printf("%s    Could not configure certificate.%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                                        }
                                        if(!SSL_CTX_use_PrivateKey(options->ctx, pkey))
                                        {
                                                status = 0;
                                                printf("%s    Could not configure private key.%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                                        }
                                }
                                PKCS12_free(pk12);
                        }
                        fclose(pk12File);
                }
                else
                {
                        printf("%s    Could not open PKCS#12 file.%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                        status = 0;
                }
        }

        // Check Cert/Key...
        if(status != 0)
        {
                if(!SSL_CTX_check_private_key(options->ctx))
                {
                        printf("%s    Private key does not match certificate.%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                        return false;
                }
                else
                        return true;
        }
        else
                return false;
}
#endif
//! ----------------------------------------------------------------------------
//! util
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int ocsp_certid_print(BIO *l_stdout_bp, OCSP_CERTID *a, int a_indent)
{
        BIO_printf(l_stdout_bp, "%*sCertificate ID:\n",    a_indent, ""); a_indent += 2;
        BIO_printf(l_stdout_bp, "%*sHash Algorithm: ",     a_indent, ""); i2a_ASN1_OBJECT(l_stdout_bp,  a->hashAlgorithm.algorithm);
        BIO_printf(l_stdout_bp, "\n%*sIssuer Name Hash: ", a_indent, ""); i2a_ASN1_STRING(l_stdout_bp,  &a->issuerNameHash, 0);
        BIO_printf(l_stdout_bp, "\n%*sIssuer Key Hash: ",  a_indent, ""); i2a_ASN1_STRING(l_stdout_bp,  &a->issuerKeyHash, 0);
        BIO_printf(l_stdout_bp, "\n%*sSerial Number: ",    a_indent, ""); i2a_ASN1_INTEGER(l_stdout_bp, &a->serialNumber);
        BIO_printf(l_stdout_bp, "\n");
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int ocsp_resp_cb(SSL *a_ssl, void *a_unused)
{
        BIO *l_stdout_bp = NULL;
#if 0
        const unsigned char *p = NULL;
        int len = 0;
        int i = 0;
        long l = 0;
        OCSP_CERTSTATUS *l_cs = NULL;
        OCSP_REVOKEDINFO *l_crt_rev = NULL;
        OCSP_SINGLERESP *l_sr = NULL;
        OCSP_RESPBYTES *rb = NULL;
#endif
        int32_t l_s;
        const char* l_chr;
        long l_tmp;
        const unsigned char* l_ocsp_ptr = NULL;
        OCSP_RESPONSE* l_ocsp_resp = NULL;
        OCSP_RESPBYTES* l_ocsp_respbytes = NULL;
        OCSP_BASICRESP *l_ocsp_basicresp = NULL;
        OCSP_RESPDATA *l_ocsp_respdata = NULL;
        OCSP_RESPID *l_ocsp_respid = NULL;
        // -------------------------------------------------
        // setup bio stdout output
        // -------------------------------------------------
        l_stdout_bp = BIO_new_fp(stdout, BIO_NOCLOSE);
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        int l_len;
        l_len = SSL_get_tlsext_status_ocsp_resp(a_ssl, &l_ocsp_ptr);
        if(l_ocsp_ptr == NULL)
        {
                //BIO_puts(l_stdout_bp, "No OCSP response recieved.\n\n");
                printf("    No OCSP response recieved.\n");
                goto cleanup;
        }
        UNUSED(l_len);
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        l_ocsp_resp = d2i_OCSP_RESPONSE(NULL, &l_ocsp_ptr, l_len);
        if(l_ocsp_resp == NULL)
        {
                printf("    OCSP response parse error.\n");
                BIO_dump_indent(l_stdout_bp, (char *)l_ocsp_ptr, l_len, 4);
                goto cleanup;
        }
        // -------------------------------------------------
        // read resp
        // -------------------------------------------------
        l_ocsp_respbytes = l_ocsp_resp->responseBytes;
        l_tmp = ASN1_ENUMERATED_get(l_ocsp_resp->responseStatus);
        l_chr = OCSP_response_status_str(l_tmp);
        printf("    OCSP Response Status: %s (0x%lx)\n", l_chr, l_tmp);
        if(l_ocsp_respbytes == NULL)
        {
                return 1;
        }
        printf("    Reponse Type: ");
        l_s = i2a_ASN1_OBJECT(l_stdout_bp, l_ocsp_respbytes->responseType);
        if(l_s <= 0)
        {
                goto cleanup;
        }
        l_s = OBJ_obj2nid(l_ocsp_respbytes->responseType);
        if(l_s != NID_id_pkix_OCSP_basic)
        {
                printf("(unknown response type)\n");
                return 1;
        }
        printf("\n");
        // -------------------------------------------------
        // version
        // -------------------------------------------------
        l_ocsp_basicresp = OCSP_response_get1_basic(l_ocsp_resp);
        if(l_ocsp_basicresp == NULL)
        {
                goto cleanup;
        }
        l_ocsp_respdata = &(l_ocsp_basicresp->tbsResponseData);
        l_tmp = ASN1_INTEGER_get(l_ocsp_respdata->version);
        printf("    Version: %lu (0x%lx)\n", l_tmp + 1, l_tmp);
        // -------------------------------------------------
        // responder id
        // -------------------------------------------------
        printf("    Responder Id: ");
        l_ocsp_respid = &(l_ocsp_respdata->responderId);
        switch(l_ocsp_respid->type)
        {
        case V_OCSP_RESPID_NAME:
        {
                X509_NAME_print_ex(l_stdout_bp, l_ocsp_respid->value.byName, 0, XN_FLAG_ONELINE);
                break;
        }
        case V_OCSP_RESPID_KEY:
        {
                i2a_ASN1_STRING(l_stdout_bp, l_ocsp_respid->value.byKey, 0);
                break;
        }
        default:
        {
                break;
        }
        }
        printf("\n");
        // -------------------------------------------------
        // produced
        // -------------------------------------------------
        printf("    Produced At: ");
        if(!ASN1_GENERALIZEDTIME_print(l_stdout_bp, l_ocsp_respdata->producedAt))
        {
                goto cleanup;
        }
        printf("\n");
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        printf("    Responses: \n");
        for(int i_r = 0; i_r < sk_OCSP_SINGLERESP_num(l_ocsp_respdata->responses); ++i_r)
        {
                // -----------------------------------------
                // update
                // -----------------------------------------
                OCSP_SINGLERESP *l_sr = NULL;
                l_sr = sk_OCSP_SINGLERESP_value(l_ocsp_respdata->responses, i_r);
                if(!l_sr)
                {
                        continue;
                }
                OCSP_CERTID *l_cid = NULL;
                l_cid = l_sr->certId;
                int32_t l_unused;
                l_unused = ocsp_certid_print(l_stdout_bp, l_cid, 4);
                UNUSED(l_unused);
                // -----------------------------------------
                // status
                // -----------------------------------------
                OCSP_CERTSTATUS *l_cs = NULL;
                l_cs = l_sr->certStatus;
                printf("    Cert Status: ");
                if(l_cs->type == V_OCSP_CERTSTATUS_GOOD)
                {
                        printf("%s%s%s", ANSI_COLOR_FG_GREEN, OCSP_cert_status_str(l_cs->type), ANSI_COLOR_OFF);
                }
                else if(l_cs->type == V_OCSP_CERTSTATUS_REVOKED)
                {
                        OCSP_REVOKEDINFO *l_crt_rev = NULL;
                        printf("%s%s%s", ANSI_COLOR_FG_RED, OCSP_cert_status_str(l_cs->type), ANSI_COLOR_OFF);
                        l_crt_rev = l_cs->value.revoked;
                        printf("\n");
                        // ---------------------------------
                        // revocation time
                        // ---------------------------------
                        printf("    Revocation Time: ");
                        if(!ASN1_GENERALIZEDTIME_print(l_stdout_bp, l_crt_rev->revocationTime))
                        {
                                goto cleanup;
                        }
                        // ---------------------------------
                        // get revocation reason
                        // ---------------------------------
                        if(l_crt_rev->revocationReason)
                        {
                                l_tmp = ASN1_ENUMERATED_get(l_crt_rev->revocationReason);
                                l_chr = OCSP_crl_reason_str(l_tmp);
                                printf("\n");
                                printf("    Revocation Reason: %s (0x%lx)", l_chr, l_tmp);
                        }
                }
                else
                {
                        printf("%s%s%s", ANSI_COLOR_FG_YELLOW, OCSP_cert_status_str(l_cs->type), ANSI_COLOR_OFF);
                }
                printf("\n");
                // -----------------------------------------
                // update
                // -----------------------------------------
                printf("    This Update: ");
                if(!ASN1_GENERALIZEDTIME_print(l_stdout_bp, l_sr->thisUpdate))
                {
                        goto cleanup;
                }
                // -----------------------------------------
                // next update
                // -----------------------------------------
                if(l_sr->nextUpdate)
                {
                        printf("\n");
                        printf("    Next Update: ");
                        if(!ASN1_GENERALIZEDTIME_print(l_stdout_bp, l_sr->nextUpdate))
                        {
                                goto cleanup;
                        }
                }
                printf("\n");
                // -----------------------------------------
                // resp ext
                // -----------------------------------------
                if(!X509V3_extensions_print(l_stdout_bp, "    Response Single Extensions", l_sr->singleExtensions, 0, 4))
                {
                        goto cleanup;
                }
                printf("\n");
        }
        // -------------------------------------------------
        // print resp extensions
        // -------------------------------------------------
#if 0
        if(!X509V3_extensions_print(l_stdout_bp, "Response Extensions", l_ocsp_respdata->responseExtensions, 0, 4))
        {
                goto cleanup;
        }
        if(X509_signature_print(l_stdout_bp, &l_ocsp_basicresp->signatureAlgorithm, l_ocsp_basicresp->signature) <= 0)
        {
                goto cleanup;
        }
        for(int i_c = 0; i_c < sk_X509_num(l_ocsp_basicresp->certs); ++i_c)
        {
                X509_print(l_stdout_bp, sk_X509_value(l_ocsp_basicresp->certs, i_c));
                PEM_write_bio_X509(l_stdout_bp, sk_X509_value(l_ocsp_basicresp->certs, i_c));
        }
        printf("\n");
#endif
        // -------------------------------------------------
        // done
        // -------------------------------------------------
cleanup:
        printf("\n");
        if(l_ocsp_resp) { OCSP_RESPONSE_free(l_ocsp_resp); l_ocsp_resp = NULL; }
        //BIO_free(l_stdout_bp);
        return 1;
}
//! ----------------------------------------------------------------------------
//! \details: request a stapled OCSP request from the server.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t check_ocsp_request(const host_info& a_host_info, long a_tls_options)
{
        // -------------------------------------------------
        // tls conn
        // -------------------------------------------------
        int32_t l_ret = STATUS_OK;
        tls_conn l_tls_conn(a_host_info, a_tls_options);
        // -------------------------------------------------
        // setup ocsp cb
        // -------------------------------------------------
        l_tls_conn.m_opt_ctx_ocsp_cb = ocsp_resp_cb;
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_tls_conn.connect();
        if(l_s != STATUS_OK)
        {
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Setup BIO's
        // -------------------------------------------------
        BIO *l_bio_stdout = NULL;
        l_bio_stdout = BIO_new(BIO_s_file());
        if(!l_bio_stdout)
        {
                //NDBG_PRINT("error. reason: TODO\n");
                l_ret = STATUS_ERROR;
                goto cleanup;
        }
        BIO_set_fp(l_bio_stdout, stdout, BIO_NOCLOSE);
cleanup:
        // -------------------------------------------------
        // free BIO
        // -------------------------------------------------
        if(l_bio_stdout)
        {
                BIO_free(l_bio_stdout);
                l_bio_stdout = NULL;
        }
        return l_ret;
}
}

