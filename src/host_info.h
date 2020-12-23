//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    host_info.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _HOST_INFO_H
#define _HOST_INFO_H
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include <sys/socket.h>
#include <stdint.h>
#include <string>
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! \details: Host info
//! ----------------------------------------------------------------------------
struct host_info {
        std::string m_host;
        struct sockaddr_storage m_sa;
        int m_sa_len;
        int m_sock_family;
        int m_sock_type;
        int m_sock_protocol;
        host_info();
        void show(void);
};
//! ----------------------------------------------------------------------------
//! util
//! ----------------------------------------------------------------------------
int32_t lookup(const std::string &a_host,
               uint16_t a_port,
               host_info &ao_host_info,
               int a_ai_family);
}
#endif

