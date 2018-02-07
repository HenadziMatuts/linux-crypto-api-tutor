/**
 * Copyright (c) 2018 Henadzi Matuts <eyesscreasmake@rambler.ru>
 */

#include <xor_cipher.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct xor_cipher_ctx
{
	uint8_t key[XOR_CIPHER_KEY_SIZE];
};

xor_cipher_ctx* xor_cipher_allocate(uint8_t *key)
{
	xor_cipher_ctx *cipher = calloc(1, sizeof(xor_cipher_ctx));

	if (cipher && key)
	{
		xor_cipher_set_key(cipher, key);
	}

	return cipher;
}

void xor_cipher_set_key(xor_cipher_ctx *ctx, uint8_t *key)
{
	memmove(ctx->key, key, XOR_CIPHER_KEY_SIZE);
}

void xor_cipher_crypt_block(xor_cipher_ctx *ctx, uint8_t *dst, uint8_t *src)
{
	for (int i = 0; i < XOR_CIPHER_BLOCK_SIZE; i++)
	{
		dst[i] = src[i] ^ ctx->key[i];
	}
}

void xor_cipher_encrypt_cbc(xor_cipher_ctx *ctx,
		uint8_t *_dst, uint32_t len, uint8_t *_src, uint8_t *_iv)
{
	uint32_t blocks = len / XOR_CIPHER_BLOCK_SIZE;
	uint32_t leftover = len - (blocks * XOR_CIPHER_BLOCK_SIZE);

	uint8_t *dst = _dst, *src = _src, *iv = _iv;

	for (uint32_t i = 0; i < blocks; i++)
	{
		memmove(dst, src, XOR_CIPHER_BLOCK_SIZE);

		for (int j = 0; j < XOR_CIPHER_BLOCK_SIZE; j++)
		{
			dst[j] ^= iv[j];
		}

		xor_cipher_crypt_block(ctx, dst, dst);

		iv = dst;
		dst += XOR_CIPHER_BLOCK_SIZE;
		src += XOR_CIPHER_BLOCK_SIZE;
	}

	if (leftover)
	{
		memmove(dst, src, leftover);

		for (uint32_t i = 0; i < leftover; i++)
		{
			dst[i] ^= iv[i];
			dst[i] ^= ctx->key[i];
		}
	}
}

void xor_cipher_decrypt_cbc(xor_cipher_ctx *ctx,
		uint8_t *_dst, uint32_t len, uint8_t *_src, uint8_t *_iv)
{
	uint32_t blocks = len / XOR_CIPHER_BLOCK_SIZE;
	uint32_t leftover = len - (blocks * XOR_CIPHER_BLOCK_SIZE);
	uint8_t u[XOR_CIPHER_BLOCK_SIZE], iv[XOR_CIPHER_IV_SIZE];

	uint8_t *dst = _dst, *src = _src;

	memmove(iv, _iv, XOR_CIPHER_IV_SIZE);

	for (uint32_t i = 0; i < blocks; i++)
	{
		memmove(u, src, XOR_CIPHER_BLOCK_SIZE);
		xor_cipher_crypt_block(ctx, dst, src);

		for (int j = 0; j < XOR_CIPHER_BLOCK_SIZE; j++)
		{
			dst[j] ^= iv[j];
		}

		memmove(iv, u, XOR_CIPHER_IV_SIZE);
		dst += XOR_CIPHER_BLOCK_SIZE;
		src += XOR_CIPHER_BLOCK_SIZE;
	}

	if (leftover)
	{
		for (uint32_t i = 0; i < leftover; i++)
		{
			dst[i] = src[i] ^ ctx->key[i];
			dst[i] ^= iv[i];
		}
	}
}

void xor_cipher_free(xor_cipher_ctx *ctx)
{
	memset(ctx->key, 0xFF, XOR_CIPHER_KEY_SIZE);
	free(ctx);
}
