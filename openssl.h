/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_H
#define OPENSSL_H

#include <openssl/evp.h>
#include <openssl/sha.h>

struct evp_md_ctx_st {
	const EVP_MD *digest;
	ENGINE *engine;
	unsigned long flags;
	void *md_data;
	EVP_PKEY_CTX *pctx;
	int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
};

#endif // OPENSSL_H
