//: ----------------------------------------------------------------------------
//: Copyright Verizon.
//:
//: \file:    missing_ciphersuites.h
//: \details: TODO
//:
//: Licensed under the terms of the Apache 2.0 open source license.
//: Please refer to the LICENSE file in the project root for the terms.
//: ----------------------------------------------------------------------------
#ifndef _MISSING_CIPHERSUITES_H
#define _MISSING_CIPHERSUITES_H
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
namespace ns_tlsscan {
//: ----------------------------------------------------------------------------
//: missing_ciphersuite
//: ----------------------------------------------------------------------------
typedef struct missing_ciphersuite {
        // -------------------------------------------------
        // TLS protocol ID.
        // -------------------------------------------------
        uint16_t m_id;
        // -------------------------------------------------
        // IANA name, as defined in the RFCs.
        // -------------------------------------------------
        char m_protocol_name[48];
        // -------------------------------------------------
        // Bit strength of the cipher.  -1 if unknown.
        // -------------------------------------------------
        int32_t m_bits;
        // -------------------------------------------------
        // OR'ed list of V1_? defines.
        // Refers to TLS version that OpenSSL does not have
        // ciphersuite implementation for.
        // Hence, should be tested under this TLS version.
        // -------------------------------------------------
        uint32_t m_check_tls_versions;
        // -------------------------------------------------
        // OR'ed list of V1_? defines.
        // Set at run-time if ciphersuite accepted by server
        // by specified TLS version.
        // -------------------------------------------------
        uint32_t m_accepted_tls_versions;
} missing_ciphersuite_t;
//: ----------------------------------------------------------------------------
//: At run-time, get_missing_ciphers() function enumerates all ciphers
//: OpenSSL has, and compares them each to missing_ciphersuites list.
//: After 'check_tls_versions' field will have set of TLS versions OpenSSL does
//: not have an implementation for i.e.:
//:   if the TLS_RSA_WITH_IDEA_CBC_SHA cipher is set to V1_2, then OpenSSL has
//:   implementation for it for TLS v1.0 and v1.1, but not for v1.2
//: ----------------------------------------------------------------------------
extern missing_ciphersuite_t g_missing_ciphersuites[];
//: ----------------------------------------------------------------------------
//: util
//: ----------------------------------------------------------------------------
void get_missing_ciphers(void);
}
#endif

