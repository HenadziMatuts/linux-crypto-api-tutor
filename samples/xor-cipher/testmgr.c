/**
 * Copyright (c) 2018 Henadzi Matuts <eyesscreasmake@rambler.ru>
 */

#include <xor_cipher.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef enum test_t
{
	TEST_BLK_CRYPT = 0,
	TEST_CBC_ENCRYPT,
	TEST_CBC_DECRYPT,
	TEST_END,

} test_t;

typedef struct cipher_testvec_t
{ 
	test_t test;
	uint32_t len;
	char *in;
	char *result;
	char *key;
	char *iv;
	
} cipher_testvec_t;

cipher_testvec_t testvecs[] = {
	{
		.test = TEST_BLK_CRYPT,
		.key = "\x2f\x1b\x1a\xc6\xd1\xbe\xcb\xa2\xf8\x45\x66\x0d\xd2\x97\x5c\xa3",
		.in = "\xcc\x6b\x79\x0c\xdb\x55\x4f\xe5\xa0\x69\x05\x96\x11\xbe\x8c\x15",
		.result = "\xE3\x70\x63\xCA\x0A\xEB\x84\x47\x58\x2C\x63\x9B\xC3\x29\xD0\xB6",
	},
	{
		.test = TEST_BLK_CRYPT,
		.key = "\x2f\x1b\x1a\xc6\xd1\xbe\xcb\xa2\xf8\x45\x66\x0d\xd2\x97\x5c\xa3",
		.in = "\x53\xf5\xf1\xef\x67\xa5\xba\x6c\x68\x09\xb5\x7a\x24\xde\x82\x5f",
		.result = "\x7C\xEE\xEB\x29\xB6\x1B\x71\xCE\x90\x4C\xD3\x77\xF6\x49\xDE\xFC",
	},
	{
		.test = TEST_CBC_ENCRYPT,
		.key = "\xec\x8d\x93\x30\x69\x7e\xf8\x63\x0b\xf5\x58\xec\xde\x78\x24\xf2",
		.iv = "\xdb\x02\x1f\xa8\x5a\x22\x15\xcf\x49\xf7\x80\x8b\x7c\x24\xa1\xf3",
		.len = 40,
		.in = "\x6e\x96\x50\x42\x84\xd2\x7e\xe8\x44\x9b\x75\x1d\xe0\xac\x0a\x58"
			  "\xee\x40\x24\xcc\x32\xfc\x6e\xc4\xe2\xfc\xd1\xf5\x76\x6a\x45\x9a"
			  "\xe4\x88\xba\xd6\x12\x07\x28\x86",
		.result = "\x59\x19\xdc\xda\xb7\x8e\x93\x44\x06\x99\xad\x7a\x42\xf0\x8f\x59"
				  "\x5b\xd4\x6b\x26\xec\x0c\x05\xe3\xef\x90\x24\x63\xea\xe2\xee\x31"
				  "\x53\xd1\x42\xc0\x97\x75\xd5\x06",
	},
	{
		.test = TEST_CBC_DECRYPT,
		.key = "\xec\x8d\x93\x30\x69\x7e\xf8\x63\x0b\xf5\x58\xec\xde\x78\x24\xf2",
		.iv = "\xdb\x02\x1f\xa8\x5a\x22\x15\xcf\x49\xf7\x80\x8b\x7c\x24\xa1\xf3",
		.len = 32,
		.in = "\xdb\xe9\x1d\xc6\x1f\x13\x1a\x5a\x34\x2b\x90\x1e\xc3\xb1\x6f\xe9"
			  "\x52\x1b\x91\x7f\x8d\x8f\x6d\xb4\x42\x87\xad\x85\x5f\x2d\x89\x7d",
		.result = "\xec\x66\x91\x5e\x2c\x4f\xf7\xf6\x76\x29\x48\x79\x61\xed\xea\xe8"
				  "\x65\x7f\x1f\x89\xfb\xe2\x8f\x8d\x7d\x59\x65\x77\x42\xe4\xc2\x66",
	},
	{
		.test = TEST_END,
	},
};

static void dumpb(uint8_t *buffer, uint32_t len, char *label)
{
	fprintf(stderr, "%s%s%u bytes:\n", label ? label : "",
							label ? ": " : "", len);

	for (uint32_t i = 0; i < len; i++)
	{
		fprintf(stderr, "%02x ", buffer[i]);

		if (((i + 1) % 16 == 0) && ((i + 1) != len))
		{
			fprintf(stderr, "\n");
		} 
	}
	fprintf(stderr, "\n");
}

static int test_cbc(cipher_testvec_t *testvec)
{
	uint8_t dst[testvec->len];
	int encrypt = (testvec->test == TEST_CBC_ENCRYPT) ? 1 : 0;
	xor_cipher_ctx *cipher = xor_cipher_allocate((uint8_t*)testvec->key);

	if (encrypt)
	{
		xor_cipher_encrypt_cbc(cipher, dst, testvec->len,
			(uint8_t*)testvec->in, (uint8_t*)testvec->iv);
	}
	else
	{
		xor_cipher_decrypt_cbc(cipher, dst, testvec->len,
			(uint8_t*)testvec->in, (uint8_t*)testvec->iv);
	}

	xor_cipher_free(cipher);

	if (memcmp(dst, (uint8_t*)testvec->result, testvec->len))
	{
		fprintf(stderr, "cbc %sciphering test failed!\n", encrypt ? "" : "de");
		dumpb((uint8_t*)testvec->key, XOR_CIPHER_KEY_SIZE, "key");
		dumpb((uint8_t*)testvec->iv, XOR_CIPHER_IV_SIZE, "iv");
		dumpb((uint8_t*)testvec->in, testvec->len, "in");
		dumpb(dst, testvec->len, "result");
		dumpb((uint8_t*)testvec->result, testvec->len, "should be");
	
		return 0;
	}

	return 1;
}

static int test_blk(cipher_testvec_t *testvec)
{
	uint8_t dst[XOR_CIPHER_BLOCK_SIZE];
	xor_cipher_ctx *cipher = xor_cipher_allocate((uint8_t*)testvec->key);

	xor_cipher_crypt_block(cipher, dst, (uint8_t*)testvec->in);
	xor_cipher_free(cipher);

	if (memcmp(dst, (uint8_t*)testvec->result, XOR_CIPHER_BLOCK_SIZE))
	{
		fprintf(stderr, "block ciphering test failed!\n");
		dumpb((uint8_t*)testvec->key, XOR_CIPHER_KEY_SIZE, "key");
		dumpb((uint8_t*)testvec->in, XOR_CIPHER_BLOCK_SIZE, "in");
		dumpb(dst, XOR_CIPHER_BLOCK_SIZE, "result");
		dumpb((uint8_t*)testvec->result, XOR_CIPHER_BLOCK_SIZE, "should be");
	
		return 0;
	}

	return 1;
}

int main()
{
	int i = 0;
	int passed = 0;

	while (1)
	{
		cipher_testvec_t *testvec = &testvecs[i++];

		switch (testvec->test)
		{
			case TEST_BLK_CRYPT:
				passed += test_blk(testvec);
				continue;

			case TEST_CBC_ENCRYPT:
			case TEST_CBC_DECRYPT:
				passed += test_cbc(testvec);
				continue;

			case TEST_END:
				goto end;
		}
	}

end:
	i--;
	fprintf(stderr, "done %d tests, passed: %d, failed: %d\n", i, passed, i - passed);

	return 0;
}
