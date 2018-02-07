/**
 * Copyright (c) 2018 Henadzi Matuts <eyesscreasmake@rambler.ru>
 */

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define XOR_CIPHER_IV_SIZE    16
#define XOR_CIPHER_KEY_SIZE   16
#define XOR_CIPHER_BLOCK_SIZE 16

struct af_alg_skcipher
{
	int sockfd;
};

typedef enum test_t
{
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

static struct af_alg_skcipher* af_alg_allocate_skcipher(char *name)
{
	struct af_alg_skcipher *tfm = NULL;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};

	strncpy((char*)sa.salg_name, name, sizeof(sa.salg_name));

	tfm = calloc(1, sizeof(struct af_alg_skcipher));
	if (!tfm)
	{
		errno = ENOMEM;
		goto err;
	}

	tfm->sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm->sockfd == -1)
	{
		goto err;
	}

	if (bind(tfm->sockfd, (struct sockaddr*)&sa, sizeof(sa)) == -1)
	{
		goto err; 
	}

	return tfm;

err:
	if (tfm->sockfd > 0)
	{
		close(tfm->sockfd);
	}
	if (tfm)
	{
		free(tfm);
	}

	return NULL;
}

static int af_alg_skcipher_setkey(struct af_alg_skcipher *tfm,
				uint8_t *key, uint32_t keylen)
{
	return (setsockopt(tfm->sockfd, SOL_ALG, ALG_SET_KEY, key, keylen) == -1) ? 0 : 1;
}

static int af_alg_skcipher_crypt(struct af_alg_skcipher *tfm, int encrypt,
				uint8_t *_dst, uint32_t _len, uint8_t *_src,
				uint8_t *iv, uint32_t ivlen)
{
	int type = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(type)) +
			 CMSG_SPACE(offsetof(struct af_alg_iv, iv) + ivlen)];
	int op = 0;
	ssize_t len, remainig = _len;
	uint8_t *src = _src, *dst = _dst;

	op = accept(tfm->sockfd, NULL, 0);
	if (op == -1)
	{
		goto end;
	}

	memset(buf, 0, sizeof(buf));

	/* fill in af_alg cipher controll data */
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	/* operation type: encrypt or decrypt */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(type));
	memmove(CMSG_DATA(cmsg), &type, sizeof(type));

	/* initialization vector */
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = ivlen;
	memmove(ivm->iv, iv, ivlen);

	/* set data stream (scatter/gather list) */
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (remainig)
	{
		iov.iov_base = src;
		iov.iov_len = remainig;

		len = sendmsg(op, &msg, 0);
		if (len == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}

			goto end;
		}
		while (read(op, dst, len) != len)
		{
			if (errno != EINTR)
			{
				goto end;
			}
		}

		src += len;
		remainig -= len;

		/* no iv for subsequent data chunks */
		msg.msg_controllen = 0;
	}

	/* done */
	close(op);
	return 1;

end:
	if (op > 0)
	{
		close(op);
	}

	return 0;
}

static void af_alg_free_skcipher(struct af_alg_skcipher *tfm)
{
	close(tfm->sockfd);
	free(tfm);
}

static int test_cbc(cipher_testvec_t *testvec)
{
	uint8_t dst[testvec->len];
	int encrypt = (testvec->test == TEST_CBC_ENCRYPT) ? 1 : 0;
	struct af_alg_skcipher *tfm = NULL;

	tfm = af_alg_allocate_skcipher("cbc-xor-cipher");
	if (!tfm)
	{
		fprintf(stderr, "error allocating \"cbc-xor-cipher\"\n");
		goto err;
	}

	if (!af_alg_skcipher_setkey(tfm, (uint8_t*)testvec->key, XOR_CIPHER_KEY_SIZE))
	{
		fprintf(stderr, "can't set \"cbc-xor-cipher\" key\n");
		goto err;
	}

	if (!af_alg_skcipher_crypt(tfm, encrypt, dst,
			testvec->len, (uint8_t*)testvec->in,
			(uint8_t*)testvec->iv, XOR_CIPHER_IV_SIZE))
	{
		goto err;
	}

	af_alg_free_skcipher(tfm);

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
err:
	if (tfm)
	{
		af_alg_free_skcipher(tfm);
	}

	return 0;
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