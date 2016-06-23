/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "aesgcm.h"
#include "conv.h"

#include <openssl/rand.h>

#include <string.h>

uint8_t *
aesgcm_encrypt(const char *alg, EVP_PKEY *key, const uint8_t pt[], size_t ptl,
               size_t *ivl, size_t *ctl, size_t *tgl, ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *ivcttag = NULL;
    size_t kl = 0;
    va_list ap;
    int len;

    switch (str_to_enum(alg, "A128GCM", "A192GCM", "A256GCM", NULL)) {
    case 0: cph = EVP_aes_128_gcm(); break;
    case 1: cph = EVP_aes_192_gcm(); break;
    case 2: cph = EVP_aes_256_gcm(); break;
    default: return NULL;
    }

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    if ((int) kl != EVP_CIPHER_key_length(cph))
        return NULL;

    *tgl = 16;
    *ivl = EVP_CIPHER_iv_length(cph);
    ivcttag = malloc(*ivl + *tgl + ptl + EVP_CIPHER_block_size(cph) - 1);
    if (!ivcttag)
        return NULL;

    if (RAND_bytes(ivcttag, *ivl) <= 0)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, *ivl, NULL) <= 0)
        goto error;

    if (EVP_EncryptInit(ctx, NULL, k, ivcttag) <= 0)
        goto error;

    va_start(ap, tgl);
    for (const char *aad; (aad = va_arg(ap, const char *)); ) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, (uint8_t *) aad,
                              strlen(aad)) <= 0) {
            va_end(ap);
            goto error;
        }
    }
    va_end(ap);

    if (EVP_EncryptUpdate(ctx, &ivcttag[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttag[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tgl,
                            &ivcttag[*ivl + *ctl]) <= 0)
        goto error;

    EVP_CIPHER_CTX_free(ctx);
    return ivcttag;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ivcttag);
    return NULL;
}

ssize_t
aesgcm_decrypt(const char *alg, EVP_PKEY *key, const uint8_t iv[], size_t ivl,
               const uint8_t ct[], size_t ctl, const uint8_t tg[], size_t tgl,
               uint8_t pt[], ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    ssize_t ptl = 0;
    size_t kl = 0;
    int len = 0;
    va_list ap;

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return -1;

    switch (str_to_enum(alg, "A128GCM", "A192GCM", "A256GCM", NULL)) {
    case 0: cph = EVP_aes_128_gcm(); break;
    case 1: cph = EVP_aes_192_gcm(); break;
    case 2: cph = EVP_aes_256_gcm(); break;
    default: return -1;
    }

    uint8_t sk[EVP_CIPHER_key_length(cph)];
    uint8_t si[EVP_CIPHER_iv_length(cph)];
    uint8_t st[16];

    if (RAND_bytes(sk, sizeof(sk)) <= 0)
        return -1;
    if (RAND_bytes(st, sizeof(st)) <= 0)
        return -1;
    if (RAND_bytes(si, sizeof(si)) <= 0)
        return -1;

    memcpy(sk,  k, kl > sizeof(sk) ? sizeof(sk) : kl);
    memcpy(st, tg, tgl > sizeof(st) ? sizeof(st) : tgl);
    memcpy(si, iv, ivl > sizeof(si) ? sizeof(si) : ivl);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_DecryptInit(ctx, cph, sk, si) <= 0)
        goto error;

    va_start(ap, pt);
    for (const char *aad; (aad = va_arg(ap, const char *)); ) {
        if (EVP_DecryptUpdate(ctx, NULL, &len,
                              (uint8_t *) aad, strlen(aad)) <= 0) {
            va_end(ap);
            goto error;
        }
    }
    va_end(ap);

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctl) <= 0)
        goto error;
    ptl = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(st), st) <= 0)
        goto error;

    if (EVP_DecryptFinal(ctx, &pt[ptl], &len) <= 0)
        goto error;
    ptl += len;

    EVP_CIPHER_CTX_free(ctx);
    return ptl;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

uint8_t *
aesgcmkw_seal(const char *alg, EVP_PKEY *key, const uint8_t pt[], size_t ptl,
              size_t *ivl, size_t *ctl, size_t *tgl)
{
    switch (str_to_enum(alg, "A128GCMKW", "A192GCMKW", "A256GCMKW", NULL)) {
    case 0: alg = "A128GCM"; break;
    case 1: alg = "A192GCM"; break;
    case 2: alg = "A256GCM"; break;
    default: return NULL;
    }

    return aesgcm_encrypt(alg, key, pt, ptl, ivl, ctl, tgl, NULL);
}

ssize_t
aesgcmkw_unseal(const char *alg, EVP_PKEY *key, const uint8_t iv[], size_t ivl,
                const uint8_t ct[], size_t ctl, const uint8_t tg[], size_t tgl,
                uint8_t pt[])
{
    switch (str_to_enum(alg, "A128GCMKW", "A192GCMKW", "A256GCMKW", NULL)) {
    case 0: alg = "A128GCM"; break;
    case 1: alg = "A192GCM"; break;
    case 2: alg = "A256GCM"; break;
    default: return -1;
    }

    return aesgcm_decrypt(alg, key, iv, ivl, ct, ctl, tg, tgl, pt, NULL);
}
