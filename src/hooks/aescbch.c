/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"
#include "../b64.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"

static bool
mktag(const EVP_MD *md,
      const uint8_t ky[], size_t kyl,
      const uint8_t iv[], size_t ivl,
      const uint8_t ct[], size_t ctl,
      uint8_t tg[], va_list ap)
{
    uint8_t hsh[EVP_MD_size(md)];
    HMAC_CTX hctx = {};
    bool ret = false;
    uint64_t al = 0;

    if (HMAC_Init(&hctx, ky, kyl, md) <= 0)
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
    memcpy(tg, hsh, sizeof(hsh) / 2);

egress:
    HMAC_CTX_cleanup(&hctx);
    return ret;
}

static bool
generate(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bytes = NULL;
    json_t *upd = NULL;
    json_int_t len = 0;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: len = 32; break;
    case 1: len = 48; break;
    case 2: len = 64; break;
    default: return true;
    }

    if (!kty) {
        if (json_object_set_new(jwk, "kty", json_string("oct")) == -1)
            return false;
    } else if (strcmp(kty, "oct") != 0)
        return false;

    if (!bytes) {
        if (json_object_set_new(jwk, "bytes", json_integer(len)) == -1)
            return false;
    } else if (!json_is_integer(bytes) || json_integer_value(bytes) != len)
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops",
                    "encrypt", "decrypt");
    if (!upd)
        return false;

    if (json_object_update_missing(jwk, upd) == -1) {
        json_decref(upd);
        return false;
    }

    json_decref(upd);
    return true;
}

static const char *
suggest(const json_t *jwk)
{
    const char *kty = NULL;
    const char *k = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    len = jose_b64_dlen(strlen(k));

    /* Round down to the nearest hash length. */
    len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;
    len &= SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH;

    switch (len) {
    case SHA512_DIGEST_LENGTH: return "A256CBC-HS512";
    case SHA384_DIGEST_LENGTH: return "A192CBC-HS384";
    case SHA256_DIGEST_LENGTH: return "A128CBC-HS256";
    default: return NULL;
    }
}

static uint8_t *
encrypt(const char *alg, EVP_PKEY *key,
        const uint8_t pt[], size_t ptl,
        size_t *ivl, size_t *ctl, size_t *tgl, ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    const uint8_t *k = NULL;
    uint8_t *ivcttg = NULL;
    size_t kl = 0;
    va_list ap;
    int len;

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    if ((int) kl != EVP_CIPHER_key_length(cph) * 2)
        return false;

    /* Split the input key into an HMAC and encryption keys. */
    *ivl = EVP_CIPHER_iv_length(cph);
    *tgl = EVP_MD_size(md) / 2;
    ivcttg = malloc(*ivl + *tgl + ptl + EVP_CIPHER_block_size(cph) - 1);
    if (!ivcttg)
        return false;

    if (RAND_bytes(ivcttg, *ivl) <= 0)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, &k[kl / 2], ivcttg) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, &ivcttg[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttg[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    va_start(ap, tgl);
    if (!mktag(md, k, kl / 2, ivcttg, *ivl, &ivcttg[*ivl], *ctl,
               &ivcttg[*ivl + *ctl], ap)) {
        va_end(ap);
        goto error;
    }
    va_end(ap);

    EVP_CIPHER_CTX_free(ctx);
    return ivcttg;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ivcttg);
    return NULL;
}

static uint8_t *
decrypt(const char *alg, EVP_PKEY *key,
        const uint8_t iv[], size_t ivl,
        const uint8_t ct[], size_t ctl,
        const uint8_t tg[], size_t tgl,
        size_t *ptl, ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    const uint8_t *ky = NULL;
    uint8_t *pt = NULL;
    bool vfy = false;
    size_t kyl = 0;
    int len = 0;
    va_list ap;

    ky = EVP_PKEY_get0_hmac(key, &kyl);
    if (!ky)
        return NULL;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    uint8_t tag[EVP_MD_size(md) / 2];

    if (kyl != (size_t) EVP_CIPHER_key_length(cph) * 2)
        return NULL;

    if (ivl != (size_t) EVP_CIPHER_iv_length(cph))
        return NULL;

    if (tgl != sizeof(tag))
        return NULL;

    pt = malloc(ctl);
    if (!pt)
        return NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto egress;

    if (EVP_DecryptInit(ctx, cph, &ky[kyl / 2], iv) <= 0)
        goto egress;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctl) <= 0)
        goto egress;
    *ptl = len;

    if (EVP_DecryptFinal(ctx, &pt[len], &len) <= 0)
        goto egress;
    *ptl += len;

    va_start(ap, ptl);
    vfy = mktag(md, ky, kyl / 2, iv, ivl, ct, ctl, tag, ap);
    va_end(ap);

    if (vfy)
        vfy = CRYPTO_memcmp(tag, tg, sizeof(tag)) == 0;

egress:
    EVP_CIPHER_CTX_free(ctx);
    if (!vfy)
        free(pt);
    return vfy ? pt : NULL;
}

static algo_t algo = {
    .names = (const char*[]) { NAMES, NULL },
    .type = ALGO_TYPE_CRYPT,
    .generate = generate,
    .suggest = suggest,
    .encrypt = encrypt,
    .decrypt = decrypt,
};

static void __attribute__((constructor))
constructor(void)
{
    algo.next = algos;
    algos = &algo;
}
