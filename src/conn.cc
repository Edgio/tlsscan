//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    conn.cc
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "conn.h"
#include "ndebug.h"
#include "def.h"
namespace ns_tlsscan {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
conn::conn(const host_info& a_host_info):
        m_host_info(a_host_info),
        m_fd(-1)
{
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
conn::~conn(void)
{
        cleanup();
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t conn::connect(void)
{
        // -------------------------------------------------
        // setup socket
        // -------------------------------------------------
        //NDBG_PRINT("LABEL: %s --m_host_info: %p\n",
        //           get_label().c_str(),
        //           m_host_info);
        errno = 0;
        m_fd = ::socket(m_host_info.m_sock_family,
                        m_host_info.m_sock_type,
                        m_host_info.m_sock_protocol);
        //NDBG_PRINT("%sSOCKET %s[%3d]: \n", ANSI_COLOR_BG_BLUE, ANSI_COLOR_OFF, m_fd);
        if(m_fd < 0)
        {
                NDBG_PRINT("error creating socket.  reason: %s\n", ::strerror(errno));
                //NCONN_ERROR(CONN_STATUS_ERROR_INTERNAL, "LABEL[%s]: Error creating socket. Reason: %s\n", m_label.c_str(), ::strerror(errno));
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // socket timeout
        // -------------------------------------------------
        struct timeval l_tv;
        l_tv.tv_sec = 0;
        l_tv.tv_usec = 500000;
        setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&(l_tv),sizeof(struct timeval));
        // -------------------------------------------------
        // connect
        // -------------------------------------------------
        int l_c_s = 0;
        errno = 0;
        l_c_s = ::connect(m_fd,
                          ((struct sockaddr*) &(m_host_info.m_sa)),
                           (m_host_info.m_sa_len));
        //NDBG_PRINT("%sCONNECT%s[%3d]: Retry: %d Status %3d. Reason[%d]: %s\n",
        //           ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF,
        //           m_fd, l_retry_connect_count, l_connect_status,
        //           errno,
        //           ::strerror(errno));
        if(l_c_s < 0)
        {
                NDBG_PRINT("error connecting socket.  reason: %s\n", ::strerror(errno));
        }
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t conn::cleanup(void)
{
        if(m_fd <= 0)
        {
                return STATUS_OK;
        }
        // -------------------------------------------------
        // shut down connection
        // -------------------------------------------------
        int l_s;
        l_s = ::close(m_fd);
        // TODO check status???
        UNUSED(l_s);
        m_fd = -1;
        return STATUS_OK;
}
}
