/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "aeskw.h"
#include "conv.h"

#include <openssl/rand.h>

#include <string.h>

uint8_t *
aeskw_seal(const char *alg, EVP_PKEY *key, const uint8_t pt[], size_t ptl,
           size_t *ivl, size_t *ctl, size_t *tgl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *ct = NULL;
    size_t kl = 0;
    int tmp;

    switch (str_to_enum(alg, "A128KW", "A192KW", "A256KW", NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return NULL;
    }

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    if ((int) kl != EVP_CIPHER_key_length(cph))
        return NULL;

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

    ct = malloc(ptl + EVP_CIPHER_block_size(cph) * 2 - 1);
    if (!ct)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ctx, cph, NULL, k, iv) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, ct, &tmp, pt, ptl) <= 0)
        goto error;
    *ctl = tmp;

    if (EVP_EncryptFinal(ctx, &ct[tmp], &tmp) <= 0)
        goto error;
    *ctl += tmp;

    *ivl = 0;
    *tgl = 0;
    EVP_CIPHER_CTX_free(ctx);
    return ct;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ct);
    return NULL;
}

ssize_t
aeskw_unseal(const char *alg, EVP_PKEY *key, const uint8_t iv[], size_t ivl,
             const uint8_t ct[], size_t ctl, const uint8_t tg[], size_t tgl,
             uint8_t pt[])
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    ssize_t pl = -1;
    size_t kl = 0;
    int tmp = 0;

    if (iv || ivl > 0 || tg || tgl > 0)
        return -1;

    switch (str_to_enum(alg, "A128KW", "A192KW", "A256KW", NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return -1;
    }

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return -1;

    if ((int) kl != EVP_CIPHER_key_length(cph))
        return -1;

    uint8_t iiv[EVP_CIPHER_iv_length(cph)];
    memset(iiv, 0xA6, EVP_CIPHER_iv_length(cph));

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ctx, cph, NULL, k, iiv) <= 0)
        goto egress;

    if (EVP_DecryptUpdate(ctx, pt, &tmp, ct, ctl) <= 0)
        goto egress;
    pl = tmp;

    pl = EVP_DecryptFinal(ctx, &pt[tmp], &tmp) <= 0 ? -1 : tmp;

egress:
    EVP_CIPHER_CTX_free(ctx);
    return pl;
}
