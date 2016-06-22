/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <stdbool.h>

#include <openssl/evp.h>

bool
hmac(const EVP_MD *md, const uint8_t key[], size_t klen, uint8_t hsh[], ...);

const char *
hmac_suggest(EVP_PKEY *key);

uint8_t *
hmac_sign(const char *alg, EVP_PKEY *key, const char *prot, const char *payl,
          size_t *len);

bool
hmac_verify(const char *alg, EVP_PKEY *key, const char *prot, const char *payl,
            const uint8_t sig[], size_t len);
