/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "aescbch.h"
#include "conv.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string.h>

static bool
mktag(const EVP_MD *md, const uint8_t k[], size_t kl,
      const uint8_t iv[], size_t ivl,
      const uint8_t ct[], size_t ctl,
      uint8_t tg[], size_t tgl, va_list ap)
{
    uint8_t hsh[EVP_MD_size(md)];
    HMAC_CTX hctx = {};
    bool ret = false;
    uint64_t al = 0;

    if (tgl > sizeof(hsh))
        return false;

    if (HMAC_Init(&hctx, k, kl, md) <= 0)
        goto egress;

    for (const char *aad; (aad = va_arg(ap, const char *)); ) {
        al += strlen(aad);
        if (HMAC_Update(&hctx, (uint8_t *) aad, strlen(aad)) <= 0)
            goto egress;
    }

    if (HMAC_Update(&hctx, iv, ivl) <= 0)
        goto egress;

    if (HMAC_Update(&hctx, ct, ctl) <= 0)
        goto egress;

    al = htobe64(al * 8);
    if (HMAC_Update(&hctx, (uint8_t *) &al, sizeof(al)) <= 0)
        goto egress;

    ret = HMAC_Final(&hctx, hsh, NULL) > 0;
    memcpy(tg, hsh, tgl);

egress:
    HMAC_CTX_cleanup(&hctx);
    return ret;
}

static bool
vfytag(const EVP_MD *md, const uint8_t k[], size_t kl,
      const uint8_t iv[], size_t ivl,
      const uint8_t ct[], size_t ctl,
      const uint8_t tg[], size_t tgl, va_list ap)
{
    uint8_t hsh[EVP_MD_size(md)];

    if (!mktag(md, k, kl, iv, ivl, ct, ctl, hsh, tgl, ap))
        return false;

    return CRYPTO_memcmp(tg, hsh, tgl) == 0;
}

uint8_t *
aescbch_encrypt(const char *alg, EVP_PKEY *key, const uint8_t pt[], size_t ptl,
                size_t *ivl, size_t *ctl, size_t *tgl, ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    const EVP_MD *md = NULL;
    uint8_t *ivcttag = NULL;
    size_t kl = 0;
    va_list ap;
    int len;

    switch (str_to_enum(alg, "A128CBC-HS256", "A192CBC-HS384",
                        "A256CBC-HS512", NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    if ((int) kl != EVP_CIPHER_key_length(cph) * 2)
        return NULL;

    *tgl = EVP_CIPHER_key_length(cph);
    *ivl = EVP_CIPHER_iv_length(cph);
    ivcttag = malloc(*ivl + *tgl + ptl + EVP_CIPHER_block_size(cph) - 1);
    if (!ivcttag)
        return NULL;

    if (RAND_bytes(ivcttag, *ivl) <= 0)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, &k[kl / 2], ivcttag) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, &ivcttag[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttag[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    va_start(ap, tgl);
    if (!mktag(md, k, kl / 2, ivcttag, *ivl, &ivcttag[*ivl], *ctl,
               &ivcttag[*ivl + *ctl], *tgl, ap)) {
        va_end(ap);
        goto error;
    }
    va_end(ap);

    EVP_CIPHER_CTX_free(ctx);
    return ivcttag;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ivcttag);
    return NULL;
}

ssize_t
aescbch_decrypt(const char *alg, EVP_PKEY *key, const uint8_t iv[], size_t ivl,
                const uint8_t ct[], size_t ctl, const uint8_t tg[], size_t tgl,
                uint8_t pt[], ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    const uint8_t *k = NULL;
    ssize_t ptl = 0;
    size_t kl = 0;
    int len = 0;
    va_list ap;

    switch (str_to_enum(alg, "A128CBC-HS256", "A192CBC-HS384",
                        "A256CBC-HS512", NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return -1;
    }

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return -1;

    uint8_t sk[EVP_CIPHER_key_length(cph) * 2];
    uint8_t st[EVP_CIPHER_key_length(cph)];
    uint8_t si[EVP_CIPHER_iv_length(cph)];

    if (RAND_bytes(sk, sizeof(sk)) <= 0)
        goto error;
    if (RAND_bytes(st, sizeof(st)) <= 0)
        goto error;
    if (RAND_bytes(si, sizeof(si)) <= 0)
        goto error;

    memcpy(sk, k, kl > sizeof(sk) ? sizeof(sk) : kl);
    memcpy(st, tg, tgl > sizeof(st) ? sizeof(st) : tgl);
    memcpy(si, iv, ivl > sizeof(si) ? sizeof(si) : ivl);

    va_start(ap, pt);
    if (!vfytag(md, sk, sizeof(sk) / 2, si, sizeof(si), ct, ctl,
                st, sizeof(st), ap)) {
        va_end(ap);
        goto error;
    }
    va_end(ap);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_DecryptInit(ctx, cph, &sk[sizeof(sk) / 2], si) <= 0)
        goto error;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctl) <= 0)
        goto error;
    ptl = len;

    if (EVP_DecryptFinal(ctx, &pt[ptl], &len) <= 0)
        goto error;
    ptl += len;

    EVP_CIPHER_CTX_free(ctx);
    return ptl;

error:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
