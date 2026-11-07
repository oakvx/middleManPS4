#ifndef MMPS4_LIVE_CRYPTO_H
#define MMPS4_LIVE_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
/* Standalone HMAC-SHA256 for protocol authentication; no dynamic allocation. */
int mmps4_hex_key(const char *hex, unsigned char key[32]);
void mmps4_sha256(const unsigned char *bytes, size_t size, unsigned char out[32]);
void mmps4_hmac_sha256(const unsigned char *key, size_t keylen,
                       const unsigned char *data, size_t len, unsigned char out[32]);
void mmps4_hex_encode(const unsigned char *source, size_t len, char *out);
#endif
