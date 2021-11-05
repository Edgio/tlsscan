//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    conn.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _CONN_H_
#define _CONN_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <stdint.h>
#include "host_info.h"
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class conn
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        conn(const host_info& a_host_info);
        ~conn(void);
        int32_t connect(void);
        int32_t cleanup(void);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        host_info m_host_info;
        int m_fd;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        conn(const conn&);
        conn& operator=(const conn&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        // ...
};
}
#endif
