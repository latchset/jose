/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <core/core.h>
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/rsa.h>

#include <string.h>

#define NAMES "RSA1_5", "RSA-OAEP", "RSA-OAEP-256"

static bool
resolve(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bits = NULL;
    json_t *upd = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bits", &bits) == -1)
        return false;

    if (core_str2enum(alg, NAMES, NULL) >= 3)
        return true;

    if (!kty) {
        if (json_object_set_new(jwk, "kty", json_string("RSA")) == -1)
            return false;
    } else if (strcmp(kty, "RSA") != 0)
        return false;

    if (!bits) {
        if (json_object_set_new(jwk, "bits", json_integer(2048)) == -1)
            return false;
    } else if (!json_is_integer(bits) || json_integer_value(bits) < 2048)
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

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    if (strcmp(kty, "RSA") != 0)
        return NULL;

    return "RSA1_5";
}

static bool
seal(const json_t *jwe, json_t *rcp, const json_t *jwk,
     const char *alg, const json_t *cek)
{
    EVP_PKEY *key = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool ret = false;
    size_t ptl = 0;
    int tmp = 0;
    int pad = 0;

    switch (core_str2enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
    case 0: pad = RSA_PKCS1_PADDING; tmp = 11; break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; break;
    default: return false;
    }

    key = jose_openssl_jwk_to_key(jwk, JOSE_JWK_TYPE_RSA);
    if (!key)
        return false;

    pt = jose_b64_decode_buf_json(json_object_get(cek, "k"), &ptl);
    if (!pt)
        goto egress;

    if ((int) ptl >= RSA_size(key->pkey.rsa) - tmp)
        goto egress;

    ct = malloc(RSA_size(key->pkey.rsa));
    if (!ct)
        goto egress;

    tmp = RSA_public_encrypt(ptl, pt, ct, key->pkey.rsa, pad);
    if (tmp < 0)
        goto egress;

    ret = json_object_set_new(rcp, "encrypted_key",
                              jose_b64_encode_json(ct, tmp)) == 0;

egress:
    EVP_PKEY_free(key);
    free(pt);
    free(ct);
    return ret;
}

static bool
unseal(const json_t *jwe, const json_t *rcp, const json_t *jwk,
       const char *alg, json_t *cek)
{
    EVP_PKEY *key = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool ret = false;
    size_t ctl = 0;
    int tmp = 0;

    switch (core_str2enum(alg, NAMES, NULL)) {
    case 0: tmp = RSA_PKCS1_PADDING; break;
    case 1: tmp = RSA_PKCS1_OAEP_PADDING; break;
    default: return false;
    }

    key = jose_openssl_jwk_to_key(jwk, JOSE_JWK_TYPE_RSA);
    if (!key)
        goto egress;

    ct = jose_b64_decode_buf_json(json_object_get(rcp, "encrypted_key"), &ctl);
    if (!ct)
        goto egress;

    pt = malloc(ctl);
    if (!pt)
        goto egress;

    tmp = RSA_private_decrypt(ctl, ct, pt, key->pkey.rsa, tmp);
    if (tmp <= 0)
        goto egress;

    ret = json_object_set_new(cek, "k", jose_b64_encode_json(pt, tmp)) == 0;

egress:
    EVP_PKEY_free(key);
    free(pt);
    free(ct);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *algs[] = { NAMES, NULL };

    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jwe_sealer_t sealer = {
        .algs = algs,
        .suggest = suggest,
        .seal = seal,
        .unseal = unseal,
    };

    jose_jwk_register_resolver(&resolver);
    jose_jwe_register_sealer(&sealer);
}
