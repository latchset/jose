/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"
#include "../b64.h"

#include <openssl/rand.h>

#include <string.h>

#define NAMES "A128KW", "A192KW", "A256KW"

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
    case 0: len = 16; break;
    case 1: len = 24; break;
    case 2: len = 32; break;
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
                    "wrapKey", "unwrapKey");
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

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    switch (jose_b64_dlen(strlen(k))) {
    case 16: return "A128KW";
    case 24: return "A192KW";
    case 32: return "A256KW";
    default: return NULL;
    }
}

static uint8_t *
seal(const char *alg, EVP_PKEY *key,
     const uint8_t pt[], size_t ptl,
     size_t *ivl, size_t *ctl, size_t *tgl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *ct = NULL;
    size_t kl = 0;
    int tmp;

    switch (str_to_enum(alg, NAMES, NULL)) {
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

static uint8_t *
unseal(const char *alg, EVP_PKEY *key,
       const uint8_t iv[], size_t ivl,
       const uint8_t ct[], size_t ctl,
       const uint8_t tg[], size_t tgl,
       size_t *ptl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *ky = NULL;
    uint8_t *pt = NULL;
    size_t kyl = 0;
    int tmp = 0;

    if (iv || ivl > 0 || tg || tgl > 0)
        return NULL;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return NULL;
    }

    ky = EVP_PKEY_get0_hmac(key, &kyl);
    if (!ky)
        return NULL;

    if (kyl != (size_t) EVP_CIPHER_key_length(cph))
        return NULL;

    uint8_t iiv[EVP_CIPHER_iv_length(cph)];
    memset(iiv, 0xA6, EVP_CIPHER_iv_length(cph));

    pt = malloc(ctl);
    if (!pt)
        return NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ctx, cph, NULL, ky, iiv) <= 0)
        goto error;

    if (EVP_DecryptUpdate(ctx, pt, &tmp, ct, ctl) <= 0)
        goto error;
    *ptl = tmp;

    if (EVP_DecryptFinal(ctx, &pt[tmp], &tmp) <= 0)
        goto error;
    *ptl += tmp;

    EVP_CIPHER_CTX_free(ctx);
    return pt;

error:
    EVP_CIPHER_CTX_free(ctx);
    memset(pt, 0, *ptl);
    free(pt);
    return NULL;
}

static algo_t algo = {
    .names = (const char*[]) { NAMES, NULL },
    .type = ALGO_TYPE_SEAL,
    .generate = generate,
    .suggest = suggest,
    .unseal = unseal,
    .seal = seal,
};

static void __attribute__((constructor))
constructor(void)
{
    algo.next = algos;
    algos = &algo;
}
