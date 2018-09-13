#include "openssl.h"

#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void hash_heap(const EVP_MD *md, void *dst, const void *src, const size_t size)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int len = 0;

	if (EVP_DigestInit_ex(ctx, md, NULL) == false)
	{
		printf("EVP_DigestInit_ex() failed!\n");
		goto cleanup;
	}

	if (EVP_DigestUpdate(ctx, src, size) == false)
	{
		printf("EVP_DigestUpdate() failed!\n");
		goto cleanup;
	}

	if (EVP_DigestFinal_ex(ctx, dst, &len) == false)
	{
		printf("EVP_DigestFinal_ex() failed!\n");
		goto cleanup;
	}

	if (len == 0) {
		printf("EVP_DigestFinal_ex() wrote 0 bytes!\n");
	}

cleanup:
	EVP_MD_CTX_free(ctx);
}

void hash_stack(const EVP_MD *md, void *dst, const void *src, const size_t size)
{
	EVP_MD_CTX ctx;
	unsigned int len = 0;

	if (EVP_DigestInit_ex(&ctx, md, NULL) == false)
	{
		printf("EVP_DigestInit_ex() failed!\n");
		return;
	}

	if (EVP_DigestUpdate(&ctx, src, size) == false)
	{
		printf("EVP_DigestUpdate() failed!\n");
		return;
	}

	if (EVP_DigestFinal_ex(&ctx, dst, &len) == false)
	{
		printf("EVP_DigestFinal_ex() failed!\n");
		return;
	}

	if (len == 0) {
		printf("EVP_DigestFinal_ex() wrote 0 bytes!\n");
	}
}

double seconds()
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == -1) {
		printf("seconds(): clock_gettime() failed!");
	}

	return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

void print_result(double time, unsigned long count)
{
	printf("%f seconds for %lu loops.\n\n", time, count);
}

int main()
{
	const unsigned long count = 10000000;
	const void *src = "Hello, World!";

	unsigned char dst[EVP_MAX_KEY_LENGTH];
	const size_t size = strlen(src);
	double start, finish;

	printf("--- OpenSSL hashing performance benchmark ---\n\n");

	/* SHA-1 */
	printf("Testing SHA1()...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		SHA1(src, size, dst);
	}

	finish = seconds();

	print_result(finish - start, count);

	printf("Testing EVP_sha1() [stack]...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		hash_stack(EVP_sha1(), dst, src, size);
	}

	finish = seconds();

	print_result(finish - start, count);

	printf("Testing EVP_sha1() [heap]...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		hash_heap(EVP_sha1(), dst, src, size);
	}

	finish = seconds();

	print_result(finish - start, count);

	/* SHA-256 */
	printf("Testing SHA256()...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		SHA256(src, size, dst);
	}

	finish = seconds();

	print_result(finish - start, count);

	printf("Testing EVP_sha256() [stack]...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		hash_stack(EVP_sha256(), dst, src, size);
	}

	finish = seconds();

	print_result(finish - start, count);

	printf("Testing EVP_sha256() [heap]...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		hash_heap(EVP_sha256(), dst, src, size);
	}

	finish = seconds();

	print_result(finish - start, count);

	/* SHA-512 */
	printf("Testing SHA512()...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		SHA512(src, size, dst);
	}

	finish = seconds();

	print_result(finish - start, count);

	printf("Testing EVP_sha512() [stack]...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		hash_stack(EVP_sha512(), dst, src, size);
	}

	finish = seconds();

	print_result(finish - start, count);

	printf("Testing EVP_sha512() [heap]...\n");

	start = seconds();

	for (unsigned long i = 0; i < count; i++) {
		hash_heap(EVP_sha512(), dst, src, size);
	}

	finish = seconds();

	print_result(finish - start, count);
}
