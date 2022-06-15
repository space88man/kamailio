/*
 * TLS module
 *
 * Copyright (C) 2007 iptelorg GmbH
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*!
 * \file
 * \brief Kamailio TLS support :: Locking
 * \ingroup tls
 * Module: \ref tls
 */


#include <stdlib.h> /* abort() */
#include "../../core/dprint.h"
#include "../../core/locking.h"

static int n_static_locks=0;
static gen_lock_set_t* static_locks=0;

/* OpenSSL is thread-safe since 1.1.0 */


void tls_destroy_locks()
{
	if (static_locks){
		lock_set_destroy(static_locks);
		lock_set_dealloc(static_locks);
		static_locks=0;
		n_static_locks=0;
	}
}


unsigned long sr_ssl_id_f()
{
	return my_pid();
}

/* returns -1 on error, 0 on success */
int tls_init_locks()
{
/* OpenSSL is no longer supporting to set locking callbacks since 1.1.0 */
	return 0;
}
