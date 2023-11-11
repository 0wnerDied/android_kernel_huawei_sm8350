// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cryptographic API.
 *
 * Compression operations.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 */
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/string.h>
#include "internal.h"

static int crypto_compress(struct crypto_tfm *tfm,
                            const u8 *src, unsigned int slen,
                            u8 *dst, unsigned int *dlen)
{
	return tfm->__crt_alg->cra_compress.coa_compress(tfm, src, slen, dst,
	                                                 dlen);
}

static int crypto_decompress(struct crypto_tfm *tfm,
                             const u8 *src, unsigned int slen,
                             u8 *dst, unsigned int *dlen)
{
	return tfm->__crt_alg->cra_compress.coa_decompress(tfm, src, slen, dst,
	                                                   dlen);
}

#ifdef CONFIG_CRYPTO_DELTA
static int crypto_compress_delta(struct crypto_tfm *tfm,
				const u8 *src0, const u8 *src, unsigned int slen,
				u8 *dst, unsigned int *dlen, unsigned int out_max)
{
	return tfm->__crt_alg->cra_compress.coa_compress_delta(tfm, src0, src, slen, dst,
		dlen, out_max);
}

static int crypto_decompress_delta(struct crypto_tfm *tfm,
				const u8 *src, unsigned int slen,
				const u8 *dst0, u8 *dst, unsigned int *dlen)
{
	return tfm->__crt_alg->cra_compress.coa_decompress_delta(tfm, src, slen, dst0,
		dst, dlen);
}
#endif

int crypto_init_compress_ops(struct crypto_tfm *tfm)
{
	struct compress_tfm *ops = &tfm->crt_compress;

	ops->cot_compress = crypto_compress;
	ops->cot_decompress = crypto_decompress;
#ifdef CONFIG_CRYPTO_DELTA
	ops->cot_compress_delta = crypto_compress_delta;
	ops->cot_decompress_delta = crypto_decompress_delta;
#endif

	return 0;
}
