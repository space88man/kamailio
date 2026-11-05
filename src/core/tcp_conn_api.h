/*
 * Copyright 2015 (C) Orange
 * <camille.oudot@orange.com>
 * Copyright (C) 2026 S-P Chan
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef _TCP_CONN_API_H_
#define _TCP_CONN_API_H_

#include "tcp_conn.h"

/* TCP connection API for modules: change a connection by its id from any
 * process; the core applies the change where the connection's owner is
 *  - tcp_main_threads 0/1: in the calling process, as modules did before
 *  - tcp_main_threads 2: in PROC_TCP_MAIN (a command or an io_wait task)
 * Reads (state, id, rcv, type) stay direct. */

/* return codes: 1 success, -1 failure, TCPCONN_API_NOCONN unknown conid */
#define TCPCONN_API_NOCONN (-2)

/* close conid after its pending writes; reason (enum tcp_closed_reason,
 * 0 = none) is reported by the tcp:closed/timeout/reset events */
int tcpconn_close(int conid, enum tcp_closed_reason reason);

/* set the idle lifetime of conid (seconds) */
int tcpconn_set_lifetime(int conid, unsigned int secs);

/* enable (on = 1: idle, cnt, intvl) or disable TCP keepalive on conid */
int tcpconn_set_keepalive(int conid, int on, int idle, int cnt, int intvl);

/* set connection flags on conid; allowed: F_CONN_CLOSE_EV */
int tcpconn_set_flags(int conid, unsigned int flags);

#endif /* _TCP_CONN_API_H_ */
