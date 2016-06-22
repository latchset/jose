/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <openssl/evp.h>
#include <stdbool.h>

uint8_t *
rsaes_seal(const char *alg, EVP_PKEY *key, const uint8_t pt[], size_t ptl,
           size_t *ctl);

ssize_t
rsaes_unseal(const char *alg, EVP_PKEY *key, const uint8_t ct[], size_t ctl,
             uint8_t pt[]);
