/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#define NAMES "A128KW", "A192KW", "A256KW"

static bool
resolve(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bytes = NULL;
    json_t *upd = NULL;
    json_int_t len = 0;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
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

static bool
seal(const json_t *jwe, json_t *rcp, const json_t *jwk,
     const char *alg, const json_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ky = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t ptl = 0;
    size_t ctl = 0;
    int tmp;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return false;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

    ky = jose_b64_decode_buf_json(json_object_get(jwk, "k"), &kyl);
    if (!ky)
        goto egress;

    if ((int) kyl != EVP_CIPHER_key_length(cph))
        goto egress;

    pt = jose_b64_decode_buf_json(json_object_get(cek, "k"), &ptl);
    if (!pt)
        goto egress;

    ct = malloc(ptl + EVP_CIPHER_block_size(cph) * 2 - 1);
    if (!ct)
        goto egress;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto egress;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ctx, cph, NULL, ky, iv) <= 0)
        goto egress;

    if (EVP_EncryptUpdate(ctx, ct, &tmp, pt, ptl) <= 0)
        goto egress;
    ctl = tmp;

    if (EVP_EncryptFinal(ctx, &ct[tmp], &tmp) <= 0)
        goto egress;
    ctl += tmp;

    ret = json_object_set_new(rcp, "encrypted_key",
                              jose_b64_encode_json(ct, ctl)) == 0;

egress:
    EVP_CIPHER_CTX_free(ctx);
    free(ky);
    free(pt);
    free(ct);
    return ret;
}

static bool
unseal(const json_t *jwe, const json_t *rcp, const json_t *jwk,
       const char *alg, json_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ky = NULL;
    uint8_t *ct = NULL;
    uint8_t *pt = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t ctl = 0;
    size_t ptl = 0;
    int tmp = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return NULL;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

    ky = jose_b64_decode_buf_json(json_object_get(jwk, "k"), &kyl);
    if (!ky)
        goto egress;

    if ((int) kyl != EVP_CIPHER_key_length(cph))
        goto egress;

    ct = jose_b64_decode_buf_json(json_object_get(rcp, "encrypted_key"), &ctl);
    if (!ct)
        goto egress;

    pt = malloc(ctl);
    if (!pt)
        goto egress;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto egress;

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ctx, cph, NULL, ky, iv) <= 0)
        goto egress;

    if (EVP_DecryptUpdate(ctx, pt, &tmp, ct, ctl) <= 0)
        goto egress;
    ptl = tmp;

    if (EVP_DecryptFinal(ctx, &pt[tmp], &tmp) <= 0)
        goto egress;
    ptl += tmp;

    ret = json_object_set_new(cek, "k", jose_b64_encode_json(pt, ptl)) == 0;

egress:
    EVP_CIPHER_CTX_free(ctx);
    free(ky);
    free(ct);
    free(pt);
    return ret;
}

/* This is purposefully not static so that it can be reused for ECDH-ES. */
jose_jwe_sealer_t aeskw_sealer = {
    .algs = (const char *[]) { NAMES, NULL },
    .suggest = suggest,
    .seal = seal,
    .unseal = unseal,
};

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    jose_jwk_register_resolver(&resolver);
    jose_jwe_register_sealer(&aeskw_sealer);
}
