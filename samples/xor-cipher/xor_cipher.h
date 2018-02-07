/**
 * Copyright (c) 2018 Henadzi Matuts <eyesscreasmake@rambler.ru>
 */

#ifndef _XOR_CIPHER_H
#define _XOR_CIPHER_H

#define XOR_CIPHER_BLOCK_SIZE 	16
#define XOR_CIPHER_KEY_SIZE 	16
#define XOR_CIPHER_IV_SIZE 		16

struct xor_cipher_ctx;
typedef struct xor_cipher_ctx xor_cipher_ctx;

/**
 * @param key	optional cipher key
 */
xor_cipher_ctx* xor_cipher_allocate(unsigned char *key);

void xor_cipher_set_key(xor_cipher_ctx *ctx, unsigned char *key);

/**
 * @param dst 	output data
 * @param src 	input data
 */
void xor_cipher_crypt_block(xor_cipher_ctx *ctx,
			unsigned char *dst, unsigned char *src);

/**
 * @param len	input data byte length
 */
void xor_cipher_encrypt_cbc(xor_cipher_ctx *ctx, unsigned char *dst,
		unsigned int len, unsigned char *src, unsigned char *iv);

void xor_cipher_decrypt_cbc(xor_cipher_ctx *ctx, unsigned char *dst,
		unsigned int len, unsigned char *src, unsigned char *iv);

void xor_cipher_free(xor_cipher_ctx *ctx);

#endif /* _XOR_CIPHER_H */
