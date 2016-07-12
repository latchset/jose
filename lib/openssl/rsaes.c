/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
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

    if (str2enum(alg, NAMES, NULL) >= 3)
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
     const char *alg, json_t *cek)
{
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ctl = 0;
    int tmp = 0;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      tmp = 11; md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        goto egress;

    pt = jose_b64_decode_buf_json(json_object_get(cek, "k"), &ptl);
    if (!pt)
        goto egress;

    if ((int) ptl >= RSA_size(key->pkey.rsa) - tmp)
        goto egress;

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        goto egress;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0)
        goto egress;

    if (pad == RSA_PKCS1_OAEP_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
            goto egress;

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
            goto egress;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &ctl, pt, ptl) <= 0)
        goto egress;

    ct = malloc(ctl);
    if (!ct)
        goto egress;

    if (EVP_PKEY_encrypt(ctx, ct, &ctl, pt, ptl) <= 0)
        goto egress;

    ret = json_object_set_new(rcp, "encrypted_key",
                              jose_b64_encode_json(ct, ctl)) == 0;

egress:
    EVP_PKEY_CTX_free(ctx);
    clear_free(pt, ptl);
    EVP_PKEY_free(key);
    free(ct);
    return ret;
}

static bool
unseal(const json_t *jwe, const json_t *rcp, const json_t *jwk,
       const char *alg, json_t *cek)
{
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ctl = 0;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        goto egress;

    ct = jose_b64_decode_buf_json(json_object_get(rcp, "encrypted_key"), &ctl);
    if (!ct)
        goto egress;

    ptl = ctl;
    pt = malloc(ctl);
    if (!pt)
        goto egress;

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        goto egress;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0)
        goto egress;

    if (pad == RSA_PKCS1_OAEP_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
            goto egress;

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
            goto egress;
    }

    if (EVP_PKEY_decrypt(ctx, pt, &ptl, ct, ctl) <= 0)
        goto egress;

    ret = json_object_set_new(cek, "k", jose_b64_encode_json(pt, ptl)) == 0;

egress:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    clear_free(pt, ptl);
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
