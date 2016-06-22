/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "rsaes.h"
#include "conv.h"

#include <openssl/rsa.h>

uint8_t *
rsaes_seal(const char *alg, EVP_PKEY *key, const uint8_t pt[], size_t ptl,
           size_t *ctl)
{
    uint8_t *ct = NULL;
    int tmp = 0;
    int pad = 0;

    switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
    case 0: pad = RSA_PKCS1_PADDING; tmp = 11; break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; break;
    default: return NULL;
    }

    if ((int) ptl >= RSA_size(key->pkey.rsa) - tmp)
        return NULL;

    ct = malloc(RSA_size(key->pkey.rsa));
    if (!ct)
        return NULL;

    tmp = RSA_public_encrypt(ptl, pt, ct, key->pkey.rsa, pad);
    if (tmp < 0) {
        free(ct);
        return NULL;
    }

    *ctl = tmp;
    return ct;
}

ssize_t
rsaes_unseal(const char *alg, EVP_PKEY *key, const uint8_t ct[], size_t ctl,
             uint8_t pt[])
{
    int pad = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return -1;

    switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
    case 0: pad = RSA_PKCS1_PADDING; break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; break;
    default: return -1;
    }

    return RSA_private_decrypt(ctl, ct, pt, key->pkey.rsa, pad);
}
