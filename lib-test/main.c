#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pbkdf2-sha256.h"
#include "test.h"

int do_test(testvector * tv)
{
	printf("Started %s\n", tv->t);
	fflush(stdout);
	char *key = malloc(tv->dkLen);
	if (key == 0) {
		return -1;
	}

	PKCS5_PBKDF2_HMAC((unsigned char*)tv->p, tv->plen,
			(unsigned char*)tv->s, tv->slen, tv->c,
			tv->dkLen, (unsigned char*)key);

	if (memcmp(tv->dk, key, tv->dkLen) != 0) {
		// Failed
		return -1;
	}

	return 0;
}

int main()
{
	int verbose = 1;
	int i, j, k, buflen;
	unsigned char buf[1024];
	unsigned char sha2sum[32];
	sha2_context ctx;

	for (i = 0; i < 6; i++) {
		j = i % 3;
		k = i < 3;

		if (verbose != 0)
			printf("  SHA-%d test #%d: ", 256 - k * 32, j + 1);

		sha2_starts(&ctx, k);

		if (j == 2) {
			memset(buf, 'a', buflen = 1000);

			for (j = 0; j < 1000; j++)
				sha2_update(&ctx, buf, buflen);
		} else
			sha2_update(&ctx, sha2_test_buf[j],
			    sha2_test_buflen[j]);

		sha2_finish(&ctx, sha2sum);

		if (memcmp(sha2sum, sha2_test_sum[i], 32 - k * 4) != 0) {
			if (verbose != 0)
				printf("failed\n");

			return (1);
		}

		if (verbose != 0)
			printf("passed\n");
	}

	if (verbose != 0)
		printf("\n");

	for (i = 0; i < 14; i++) {
		j = i % 7;
		k = i < 7;

		if (verbose != 0)
			printf("  HMAC-SHA-%d test #%d: ", 256 - k * 32,
			    j + 1);

		if (j == 5 || j == 6) {
			memset(buf, '\xAA', buflen = 131);
			sha2_hmac_starts(&ctx, buf, buflen, k);
		} else
			sha2_hmac_starts(&ctx, sha2_hmac_test_key[j],
			    sha2_hmac_test_keylen[j], k);

		sha2_hmac_update(&ctx, sha2_hmac_test_buf[j],
		    sha2_hmac_test_buflen[j]);

		sha2_hmac_finish(&ctx, sha2sum);

		buflen = (j == 4) ? 16 : 32 - k * 4;

		if (memcmp(sha2sum, sha2_hmac_test_sum[i], buflen) != 0) {
			if (verbose != 0)
				printf("failed\n");

			return (1);
		}

		if (verbose != 0)
			printf("passed\n");
	}

	if (verbose != 0)
		printf("\n");

	testvector *tv = 0;
	int res = 0;

	testvector t1 = {
		"Test 1",
		"password", 8, "salt", 4, 1, 32,
		.dk = { 0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
			0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
			0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
			0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b }
	};

	tv = &t1;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	testvector t2 = {
		"Test 2",
		"password", 8, "salt", 4, 2, 32, {
			0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
			0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
			0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
			0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43 }
	};

	tv = &t2;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	testvector t3 = {
		"Test 3",
		"password", 8, "salt", 4, 4096, 32, {
			0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
			0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
			0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
			0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a }
	};

	tv = &t3;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	testvector t4 = {
		"Test 4",
		"password", 8, "salt", 4, 16777216, 32, {
			0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d,
			0x1f, 0x31, 0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89,
			0xf7, 0xf1, 0x79, 0xe8, 0x9b, 0x3b, 0x0b, 0xcb,
			0x17, 0xad, 0x10, 0xe3, 0xac, 0x6e, 0xba, 0x46 }
	};

	tv = &t4;
	// res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	testvector t5 = {
		"Test 5",
		"passwordPASSWORDpassword", 24,
		"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 40, {
			0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
			0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
			0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
			0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
			0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9 }
	};

	tv = &t5;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	testvector t6 = {
		"Test 6",
		"pass\0word", 9, "sa\0lt", 5, 4096, 16, {
			0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
			0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87 }
	};

	tv = &t6;
	res = do_test(tv);
	if (res != 0) {
		printf("%s failed\n", tv->t);
		return res;
	}

	return (0);
}