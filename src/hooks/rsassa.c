/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"
#include "../b64.h"

#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"

static bool
generate(json_t *jwk)
{
    const char *alg = NULL;
    const char *kty = NULL;
    json_t *bits = NULL;
    json_t *upd = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bits", &bits) == -1)
        return false;

    if (str_to_enum(alg, NAMES, NULL) >= 6)
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

    upd = json_pack("{s:s,s:[s,s]}", "use", "sig", "key_ops",
                    "sign", "verify");
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
    const char *n = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "n", &n) == -1)
        return NULL;

    if (strcmp(kty, "RSA") != 0)
        return NULL;

    len = jose_b64_dlen(strlen(n)) * 8;

    switch ((len < 4096 ? len : 4096) & (4096 | 3072 | 2048)) {
    case 4096: return "RS512";
    case 3072: return "RS384";
    case 2048: return "RS256";
    default: return NULL;
    }
}

static uint8_t *
sign(const char *alg, EVP_PKEY *key,
     const char *prot, const char *payl, size_t *len)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    uint8_t *sig = NULL;
    int pad = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Don't use small keys. RFC 7518 3.3 */
    if (RSA_size(key->pkey.rsa) < 2048 / 8)
        return NULL;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
    default: return 0;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return NULL;

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, key) < 0)
        goto error;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, prot, strlen(prot)) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, ".", 1) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, payl, strlen(payl)) < 0)
        goto error;

    if (EVP_DigestSignFinal(ctx, NULL, len) < 0)
        goto error;

    sig = malloc(*len);
    if (!sig)
        goto error;

    if (EVP_DigestSignFinal(ctx, sig, len) < 0)
        goto error;

    EVP_MD_CTX_destroy(ctx);
    return sig;

error:
    EVP_MD_CTX_destroy(ctx);
    free(sig);
    return NULL;
}

static bool
verify(const char *alg, EVP_PKEY *key,
       const char *prot, const char *payl,
       const uint8_t sig[], size_t len)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    bool ret = false;
    int pad = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Note that although RFC 7518 3.3 says we shouldn't use small keys,
     * in the interest of being liberal in the data that we receive, we
     * allow small keys only for verification. */

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
    default: return false;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto egress;

    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, key) < 0)
        goto egress;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, prot, strlen(prot)) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, ".", 1) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, payl, strlen(payl)) < 0)
        goto egress;

    ret = EVP_DigestVerifyFinal(ctx, sig, len) == 1;

egress:
    EVP_MD_CTX_destroy(ctx);
    return ret;
}

static algo_t algo = {
    .names = (const char*[]) { NAMES, NULL },
    .type = ALGO_TYPE_SIGN,
    .generate = generate,
    .suggest = suggest,
    .verify = verify,
    .sign = sign,
};

static void __attribute__((constructor))
constructor(void)
{
    algo.next = algos;
    algos = &algo;
}
