/**
 * Copyright (c) 2018 Henadzi Matuts <eyesscreasmake@rambler.ru>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/types.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

typedef enum test_t test_t;
enum test_t
{
	TEST_BLK_ENCRYPT = 0,
	TEST_BLK_DECRYPT,
	TEST_CBC_ENCRYPT,
	TEST_CBC_DECRYPT,
	TEST_END,
};

typedef struct cipher_testvec_t cipher_testvec_t;
struct cipher_testvec_t
{ 
	test_t test;
	u32 len;
	char *key;
	char *iv;
	char *in;
	char *result;
};

static struct cipher_testvec_t testvecs[] = {
	{
		.test = TEST_BLK_ENCRYPT,
		.key = "\x2f\x1b\x1a\xc6\xd1\xbe\xcb\xa2\xf8\x45\x66\x0d\xd2\x97\x5c\xa3",
		.in = "\xcc\x6b\x79\x0c\xdb\x55\x4f\xe5\xa0\x69\x05\x96\x11\xbe\x8c\x15",
		.result = "\xe3\x70\x63\xca\x0a\xeb\x84\x47\x58\x2c\x63\x9b\xc3\x29\xd0\xb6",
	},
	{
		.test = TEST_BLK_DECRYPT,
		.key = "\x2f\x1b\x1a\xc6\xd1\xbe\xcb\xa2\xf8\x45\x66\x0d\xd2\x97\x5c\xa3",
		.in = "\x53\xf5\xf1\xef\x67\xa5\xba\x6c\x68\x09\xb5\x7a\x24\xde\x82\x5f",
		.result = "\x7c\xee\xeb\x29\xb6\x1b\x71\xce\x90\x4c\xd3\x77\xf6\x49\xde\xfc",
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

static void dumpb(const u8 *buffer, u32 len, const char *label)
{
	int i;
	printk("%s%s%u bytes:\n", label ? label : "",
							label ? ": " : "", len);
	for (i = 0; i < len; i++)
	{
		printk(KERN_CONT "%02X ", buffer[i]);

		if (((i + 1) % 16 == 0) && ((i + 1) != len))
		{
			printk("\n");	
		} 
	}
	printk("\n");
}

struct cb_data_t
{
	struct completion completion;
	int err;
};

static void skcipher_cb(struct crypto_async_request *req, int error)
{
	struct cb_data_t *data = req->data;

	if (error == -EINPROGRESS)
	{
		return;
	}

	data->err = error;
	complete(&data->completion);
}

static int test_cbc(cipher_testvec_t *testvec)
{
	struct scatterlist sg;
	struct cb_data_t cb_data;
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	int encrypt = (testvec->test == TEST_CBC_ENCRYPT) ? 1 : 0; 
	u32 err;
	u8 *buf = NULL;

	tfm = crypto_alloc_skcipher("cbc-xor-cipher", 0, 0);
	if (IS_ERR(tfm))
	{
		pr_err("error allocating cbc-xor-cipher: %ld\n", PTR_ERR(tfm));
		goto exit;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
	{
		pr_err("error allocating skcipher request\n");
		goto exit;
	}

	buf = kmalloc(testvec->len, GFP_KERNEL);
	if (!buf)
	{
		pr_err("memory allocation error\n");
		goto exit;
	}

	memmove(buf, (u8*)testvec->in, testvec->len);
	sg_init_one(&sg, buf, testvec->len);

	crypto_skcipher_setkey(tfm, (u8*)testvec->key, 16);
	skcipher_request_set_crypt(req, &sg, &sg, testvec->len, (u8*)testvec->iv);

	skcipher_request_set_callback(req, 0, skcipher_cb, &cb_data);
	init_completion(&cb_data.completion);

	err = (encrypt) ? crypto_skcipher_encrypt(req)
			: crypto_skcipher_decrypt(req);
	switch (err)
	{
		case 0:
			break;

		case -EINPROGRESS:
		case -EBUSY:
			wait_for_completion(&cb_data.completion);
			err = cb_data.err;
			if (!err)
			{
				break;
			}

		default:
			pr_err("failed with error: %d\n", err);
			goto exit;
	}

	if (memcmp(buf, testvec->result, testvec->len))
	{
		pr_err("cbc %sciphering test failed!\n", encrypt ? "" : "de");
		dumpb((u8*)testvec->key, 16, "key");
		dumpb((u8*)testvec->iv, 16, "iv");
		dumpb((u8*)testvec->in, testvec->len, "in");
		dumpb(buf, testvec->len, "result");
		dumpb((u8*)testvec->result, testvec->len, "should be");

		goto exit;
	}

	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	kfree(buf);

	return 1;

exit:
	if (buf)
	{
		kfree(buf);
	}
	if (req)
	{
		skcipher_request_free(req);
	}
	if (tfm)
	{
		crypto_free_skcipher(tfm);
	}

	return 0;
}

static int test_blk(cipher_testvec_t *testvec)
{
	struct crypto_cipher *tfm = NULL;
	int encrypt = (testvec->test == TEST_BLK_ENCRYPT) ? 1 : 0;
	u8 dst[16];

	tfm = crypto_alloc_cipher("xor-cipher", 0, 0);
	if (IS_ERR(tfm))
	{
		pr_err("error allocating xor-cipher: %ld\n", PTR_ERR(tfm));
		return 0;
	}

	crypto_cipher_setkey(tfm, (u8*)testvec->key, 16);

	if (encrypt)
	{
		crypto_cipher_encrypt_one(tfm, dst, (u8*)testvec->in);
	}
	else
	{
		crypto_cipher_decrypt_one(tfm, dst, (u8*)testvec->in);
	}

	crypto_free_cipher(tfm);

	if (memcmp(dst, testvec->result, 16))
	{
		pr_err("block %sciphering test failed!\n", encrypt ? "" : "de");
		dumpb((u8*)testvec->key, 16, "key");
		dumpb((u8*)testvec->in, 16, "in");
		dumpb(dst, 16, "result");
		dumpb((u8*)testvec->result, 16, "should be");

		return 0;
	}

	return 1;
}

static int __init init(void)
{
	int i = 0;
	int passed = 0;

	if (!crypto_has_cipher("xor-cipher", 0, 0))
	{
		pr_err("no \"xor-cipher\" loaded in kernel\n");
		return -1;
	}
	if (!crypto_has_skcipher("cbc-xor-cipher", 0, 0))
	{
		pr_err("no \"cbc-xor-cipher\" loaded in kernel\n");
		return -1;
	}

	while (1)
	{
		cipher_testvec_t *testvec = &testvecs[i++];

		switch (testvec->test)
		{
			case TEST_BLK_ENCRYPT:
			case TEST_BLK_DECRYPT:
				passed += test_blk(testvec);
				continue;

			case TEST_CBC_ENCRYPT:
			case TEST_CBC_DECRYPT:
				passed += test_cbc(testvec);
				continue;

			case TEST_END:
				goto exit;

			default:
				continue;
		}
	}
	
exit:
	i--;
	printk(KERN_INFO "done %d tests, passed: %d, failed: %d\n", i, passed, i - passed);

	return -1;
}

static void __exit fini(void)
{
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Henadzi Matuts");
MODULE_DESCRIPTION("XOR-cipher testing module");
