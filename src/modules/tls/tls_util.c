/*
 * TLS module
 *
 * Copyright (C) 2005 iptelorg GmbH
 * Copyright (C) 2013 Motorola Solutions, Inc.
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
 * \brief Kamailio TLS support :: Common functions
 * \ingroup tls
 * Module: \ref tls
 */


#define _GNU_SOURCE 1 /* Needed for strndup */

#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include "../../core/mem/shm_mem.h"
#include "../../core/globals.h"
#include "../../core/dprint.h"
#include "../../core/ip_addr.h"
#include "../../core/socket_info.h"
#include "../../core/udp_server.h"
#include "../../core/forward.h"
#include "../../core/resolve.h"

#include "tls_mod.h"
#include "tls_util.h"


extern int *ksr_tls_keylog_mode;
extern str ksr_tls_keylog_file;
extern str ksr_tls_keylog_peer;

static gen_lock_t *ksr_tls_keylog_file_lock = NULL;
static dest_info_t ksr_tls_keylog_peer_dst;

/*
 * Make a shared memory copy of ASCII zero terminated string
 * Return value: -1 on error
 *                0 on success
 */
int shm_asciiz_dup(char **dest, char *val)
{
	char *ret;
	int len;

	if(!val) {
		*dest = NULL;
		return 0;
	}

	len = strlen(val);
	ret = shm_malloc(len + 1);
	if(!ret) {
		ERR("No memory left\n");
		return -1;
	}
	memcpy(ret, val, len + 1);
	*dest = ret;
	return 0;
}


/*
 * Delete old TLS configuration that is not needed anymore
 */
void collect_garbage(void)
{
	tls_domains_cfg_t *prev, *cur, *next;

	/* Make sure we do not run two garbage collectors
	      * at the same time
	      */
	lock_get(tls_domains_cfg_lock);

	/* Skip the current configuration, garbage starts
	      * with the 2nd element on the list
	      */
	prev = *tls_domains_cfg;
	cur = (*tls_domains_cfg)->next;

	while(cur) {
		next = cur->next;
		if(atomic_get(&cur->ref_count) == 0) {
			/* Not referenced by any existing connection */
			prev->next = cur->next;
			tls_free_cfg(cur);
		} else {
			/* Only update prev if we didn't remove cur */
			prev = cur;
		}
		cur = next;
	}

	lock_release(tls_domains_cfg_lock);
}

/*
 * Get any leftover errors from OpenSSL and print them.
 * ERR_get_error() also removes the error from the OpenSSL error stack.
 * This is useful to call before any SSL_* IO calls to make sure
 * we don't have any leftover errors from previous calls (OpenSSL docs).
 */
void tls_openssl_clear_errors(void)
{
	int i;
	char err[256];
	while((i = ERR_get_error())) {
		ERR_error_string(i, err);
		INFO("clearing leftover error before SSL_* calls: %s\n", err);
	}
}

/**
 *
 */
int ksr_tls_keylog_file_init(void)
{
	if(ksr_tls_keylog_mode == NULL) {
		return 0;
	}
	if(!((*ksr_tls_keylog_mode & KSR_TLS_KEYLOG_MODE_INIT)
			   && (*ksr_tls_keylog_mode & KSR_TLS_KEYLOG_MODE_FILE))) {
		return 0;
	}
	if(ksr_tls_keylog_file.s == NULL || ksr_tls_keylog_file.len <= 0) {
		return -1;
	}
	if(ksr_tls_keylog_file_lock != NULL) {
		return 0;
	}
	ksr_tls_keylog_file_lock = lock_alloc();
	if(ksr_tls_keylog_file_lock == NULL) {
		return -2;
	}
	if(lock_init(ksr_tls_keylog_file_lock) == NULL) {
		return -3;
	}
	return 0;
}

/**
 *
 */
/* clang-format off */
static const char *ksr_tls_keylog_vfilters[] = {
	"CLIENT_RANDOM ",
	"CLIENT_HANDSHAKE_TRAFFIC_SECRET ",
	"SERVER_HANDSHAKE_TRAFFIC_SECRET ",
	"EXPORTER_SECRET ",
	"CLIENT_TRAFFIC_SECRET_0 ",
	"SERVER_TRAFFIC_SECRET_0 ",
	NULL
};
/* clang-format on */

/**
 *
 */
int ksr_tls_keylog_vfilter_match(const char *line)
{
	int i;

	for(i = 0; ksr_tls_keylog_vfilters[i] != NULL; i++) {
		if(strcasecmp(ksr_tls_keylog_vfilters[i], line) == 0) {
			return 1;
		}
	}
	return 0;
}

/**
 *
 */
int ksr_tls_keylog_file_write(const SSL *ssl, const char *line)
{
	FILE *lf = NULL;
	int ret = 0;

	if(ksr_tls_keylog_file_lock == NULL) {
		return 0;
	}

	lock_get(ksr_tls_keylog_file_lock);
	lf = fopen(ksr_tls_keylog_file.s, "a");
	if(lf) {
		fprintf(lf, "%s\n", line);
		fclose(lf);
	} else {
		LM_ERR("failed to open keylog file: %s\n", ksr_tls_keylog_file.s);
		ret = -1;
	}
	lock_release(ksr_tls_keylog_file_lock);
	return ret;
}


/**
 *
 */
int ksr_tls_keylog_peer_init(void)
{
	int proto;
	str host;
	int port;

	if(ksr_tls_keylog_mode == NULL) {
		return 0;
	}
	if(!((*ksr_tls_keylog_mode & KSR_TLS_KEYLOG_MODE_INIT)
			   && (*ksr_tls_keylog_mode & KSR_TLS_KEYLOG_MODE_PEER))) {
		return 0;
	}
	if(ksr_tls_keylog_peer.s == NULL || ksr_tls_keylog_peer.len <= 0) {
		return -1;
	}
	init_dest_info(&ksr_tls_keylog_peer_dst);
	if(parse_phostport(ksr_tls_keylog_peer.s, &host.s, &host.len, &port, &proto)
			!= 0) {
		LM_CRIT("invalid peer addr parameter <%s>\n", ksr_tls_keylog_peer.s);
		return -2;
	}
	if(proto != PROTO_UDP) {
		LM_ERR("only udp supported in peer addr <%s>\n", ksr_tls_keylog_peer.s);
		return -3;
	}
	ksr_tls_keylog_peer_dst.proto = proto;
	if(sip_hostport2su(&ksr_tls_keylog_peer_dst.to, &host, port,
			   &ksr_tls_keylog_peer_dst.proto)
			!= 0) {
		LM_ERR("failed to resolve <%s>\n", ksr_tls_keylog_peer.s);
		return -4;
	}

	return 0;
}

/**
 *
 */
int ksr_tls_keylog_peer_send(const SSL *ssl, const char *line)
{
	if(ksr_tls_keylog_mode == NULL) {
		return 0;
	}
	if(!((*ksr_tls_keylog_mode & KSR_TLS_KEYLOG_MODE_INIT)
			   && (*ksr_tls_keylog_mode & KSR_TLS_KEYLOG_MODE_PEER))) {
		return 0;
	}

	if(ksr_tls_keylog_peer_dst.send_sock == NULL) {
		ksr_tls_keylog_peer_dst.send_sock =
				get_send_socket(NULL, &ksr_tls_keylog_peer_dst.to, PROTO_UDP);
		if(ksr_tls_keylog_peer_dst.send_sock == NULL) {
			LM_ERR("no send socket for <%s>\n", ksr_tls_keylog_peer.s);
			return -2;
		}
	}

	if(udp_send(&ksr_tls_keylog_peer_dst, (char *)line, strlen(line)) < 0) {
		LM_ERR("failed to send to <%s>\n", ksr_tls_keylog_peer.s);
		return -1;
	}
	return 0;
}


char *convert_X509_to_DER(X509 *cert, int *len)
{
	char *result = NULL;

	BIO *bio = BIO_new(BIO_s_mem());
	if(i2d_X509_bio(bio, cert)) {
		BUF_MEM *mem;
		BIO_get_mem_ptr(bio, &mem);
		result = shm_malloc(mem->length);
		memcpy(result, mem->data, mem->length);
		*len = mem->length;
	}
	BIO_free(bio);

	return result;
}

X509 *convert_DER_to_X509(char *der_bytes, int len)
{
	if(!der_bytes)
		return NULL;
	BIO *mem_bio = BIO_new_mem_buf(der_bytes, len);
	X509 *x = d2i_X509_bio(mem_bio, NULL);
	BIO_free(mem_bio);

	return x;
}

char *stack_to_pkcs7_DER(STACK_OF(X509) * sk, int *out_len)
{
	*out_len = 0;
	if(!sk)
		return NULL;

	// 1. Initialize the PKCS7 object as "SignedData"
	PKCS7 *p7 = PKCS7_new();
	if(!p7)
		return NULL;

	// This tells OpenSSL this is a container for signatures/certs
	if(!PKCS7_set_type(p7, NID_pkcs7_signed)) {
		PKCS7_free(p7);
		return NULL;
	}

	// 2. Add the certificates from the stack
	for(int i = 0; i < sk_X509_num(sk); i++) {
		X509 *cert = sk_X509_value(sk, i);
		// PKCS7_add_certificate is simpler than the CMS version
		PKCS7_add_certificate(p7, cert);
	}

	// 3. Use the BIO trick to encode to DER
	BIO *out = BIO_new(BIO_s_mem());
	if(i2d_PKCS7_bio(out, p7) <= 0) {
		BIO_free(out);
		PKCS7_free(p7);
		return NULL;
	}

	// 4. Extract buffer from BIO
	BUF_MEM *bptr;
	BIO_get_mem_ptr(out, &bptr);

	char *der = shm_malloc(bptr->length);
	if(der) {
		memcpy(der, bptr->data, bptr->length);
		*out_len = (int)bptr->length;
	}

	// Cleanup
	BIO_free(out);
	PKCS7_free(p7);

	return der;
}

STACK_OF(X509) * pkcs7_DER_to_stack(const char *der_bytes, int len)
{
	if(!der_bytes || len <= 0)
		return NULL;

	// 1. Load DER bytes into a Memory BIO
	BIO *mem = BIO_new_mem_buf(der_bytes, len);
	if(!mem)
		return NULL;

	// 2. Parse the BIO into a PKCS7 object
	PKCS7 *p7 = d2i_PKCS7_bio(mem, NULL);
	BIO_free(mem); // Content is now in p7, can free the BIO

	if(!p7)
		return NULL;

	// 3. Verify it is actually a SignedData type (which holds certs)
	if(!PKCS7_type_is_signed(p7) || !p7->d.sign) {
		PKCS7_free(p7);
		return NULL;
	}

	// 4. Extract the certificate stack
	// We use X509_chain_up_ref to create a new stack where the caller
	// owns the references to the certificates.
	STACK_OF(X509) *internal_stack = p7->d.sign->cert;
	STACK_OF(X509) *out_stack = sk_X509_new_null();

	if(internal_stack) {
		for(int i = 0; i < sk_X509_num(internal_stack); i++) {
			X509 *cert = sk_X509_value(internal_stack, i);
			X509_up_ref(cert); // Increment ref count so we can free p7 safely
			sk_X509_push(out_stack, cert);
		}
	}

	// 5. Cleanup the container
	PKCS7_free(p7);

	return out_stack;
}
