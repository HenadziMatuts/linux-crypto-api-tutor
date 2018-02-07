/**
 * Copyright (c) 2018 Henadzi Matuts <eyesscreasmake@rambler.ru>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/types.h>
#include <crypto/skcipher.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>

#define XOR_CIPHER_IV_SIZE    16
#define XOR_CIPHER_KEY_SIZE   16
#define XOR_CIPHER_BLOCK_SIZE 16

struct xor_cipher_ctx
{
	u8 key[XOR_CIPHER_KEY_SIZE];
};

static int xor_cipher_setkey(struct crypto_tfm *tfm, const u8 *key,
								unsigned int len)
{
	struct xor_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;

	if (len != XOR_CIPHER_KEY_SIZE)
	{
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	memmove(ctx->key, key, XOR_CIPHER_KEY_SIZE);
	return 0;
}

static void xor_cipher_crypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	struct xor_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;

	for (i = 0; i < XOR_CIPHER_BLOCK_SIZE; i++)
	{
		out[i] = in[i] ^ ctx->key[i];
	}
}

static int xor_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
									unsigned int len)
{
	return xor_cipher_setkey(crypto_skcipher_tfm(tfm), key, len);
}

static int cbc_encrypt(struct skcipher_request *req)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(crypto_skcipher_reqtfm(req));
	struct xor_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct skcipher_walk walk;
	u32 nbytes;
	int i, blocks;
	u8 *src, *dst, *iv;

	skcipher_walk_virt(&walk, req, true);
	iv = walk.iv;

	while ((nbytes = walk.nbytes) >= XOR_CIPHER_BLOCK_SIZE)
	{
		src = (u8*)walk.src.virt.addr;
		dst = (u8*)walk.dst.virt.addr;
		blocks = nbytes / XOR_CIPHER_BLOCK_SIZE;

		while (blocks)
		{
			for (i = 0; i < XOR_CIPHER_BLOCK_SIZE; i++)
			{
				dst[i] = src[i] ^ iv[i];
			}

			xor_cipher_crypt(tfm, dst, dst);
			iv = dst;

			src += XOR_CIPHER_BLOCK_SIZE;
			dst += XOR_CIPHER_BLOCK_SIZE;
			blocks--;
		}
		
		nbytes &= XOR_CIPHER_BLOCK_SIZE - 1;
		skcipher_walk_done(&walk, nbytes);
	}

	if ((nbytes = walk.nbytes))
	{
		src = (u8*)walk.src.virt.addr;
		dst = (u8*)walk.dst.virt.addr;

		for (i = 0; i < nbytes; i++)
		{
			dst[i] = src[i] ^ iv[i];
			dst[i] ^= ctx->key[i];
		}

		skcipher_walk_done(&walk, 0);
	}

	return 0;
}

static int cbc_decrypt(struct skcipher_request *req)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(crypto_skcipher_reqtfm(req));
	struct xor_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct skcipher_walk walk;
	u8 u[XOR_CIPHER_BLOCK_SIZE], iv[XOR_CIPHER_BLOCK_SIZE];
	u32 nbytes;
	int i, blocks;
	u8 *src, *dst;

	skcipher_walk_virt(&walk, req, true);
	memmove(iv, walk.iv, XOR_CIPHER_IV_SIZE);

	while ((nbytes = walk.nbytes) >= XOR_CIPHER_BLOCK_SIZE)
	{
		src = (u8*)walk.src.virt.addr;
		dst = (u8*)walk.dst.virt.addr;
		blocks = nbytes / XOR_CIPHER_BLOCK_SIZE;

		while (blocks)
		{
			memmove(u, src, XOR_CIPHER_BLOCK_SIZE);
			xor_cipher_crypt(tfm, dst, src);

			for (i = 0; i < XOR_CIPHER_BLOCK_SIZE; i++)
			{
				dst[i] ^= iv[i];
			}

			memmove(iv, u, XOR_CIPHER_IV_SIZE);

			dst += XOR_CIPHER_BLOCK_SIZE;
			src += XOR_CIPHER_BLOCK_SIZE;
			blocks--;
		}

		nbytes &= XOR_CIPHER_BLOCK_SIZE - 1;
		skcipher_walk_done(&walk, nbytes);
	}

	if ((nbytes = walk.nbytes))
	{
		src = (u8*)walk.src.virt.addr;
		dst = (u8*)walk.dst.virt.addr;

		for (i = 0; i < nbytes; i++)
		{
			dst[i] = src[i] ^ ctx->key[i];
			dst[i] ^= iv[i];
		}

		skcipher_walk_done(&walk, 0);
	}

	return 0;
}

static struct crypto_alg xor_cipher = {
	.cra_name = "xor-cipher",
	.cra_driver_name = "xor-cipher-generic",
	.cra_priority = 100,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = XOR_CIPHER_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct xor_cipher_ctx),
	.cra_module = THIS_MODULE,
	.cra_u = {
		.cipher = {
			.cia_min_keysize = XOR_CIPHER_KEY_SIZE,
			.cia_max_keysize = XOR_CIPHER_KEY_SIZE,
			.cia_setkey	= xor_cipher_setkey,
			.cia_encrypt = xor_cipher_crypt,
			.cia_decrypt = xor_cipher_crypt
		}
	}
};

static struct skcipher_alg cbc_xor_cipher = {
	.base = {
		.cra_name = "cbc(xor-cipher)",
		.cra_driver_name = "cbc-xor-cipher",
		.cra_priority = 400,
		.cra_flags = CRYPTO_ALG_ASYNC,
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct xor_cipher_ctx),
		.cra_module	= THIS_MODULE,
	},
	.min_keysize = XOR_CIPHER_KEY_SIZE,
	.max_keysize = XOR_CIPHER_KEY_SIZE,
	.ivsize	= XOR_CIPHER_IV_SIZE,
	.setkey	= xor_skcipher_setkey,
	.encrypt = cbc_encrypt,
	.decrypt = cbc_decrypt,
	.chunksize = XOR_CIPHER_BLOCK_SIZE,
};

static int __init xor_cipher_init(void)
{
	crypto_register_alg(&xor_cipher);
	return crypto_register_skcipher(&cbc_xor_cipher);
}

static void __exit xor_cipher_exit(void)
{
	crypto_unregister_alg(&xor_cipher);
	crypto_unregister_skcipher(&cbc_xor_cipher);
}

module_init(xor_cipher_init);
module_exit(xor_cipher_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Henadzi Matuts");
MODULE_DESCRIPTION("XOR-cipher module");
