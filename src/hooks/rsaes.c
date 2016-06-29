/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"

#include <openssl/rsa.h>

#include <string.h>

#define NAMES "RSA1_5", "RSA-OAEP", "RSA-OAEP-256"

static bool
generate(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bits = NULL;
    json_t *upd = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bits", &bits) == -1)
        return false;

    if (str_to_enum(alg, NAMES, NULL) >= 3)
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

static uint8_t *
seal(const char *alg, EVP_PKEY *key,
     const uint8_t pt[], size_t ptl,
     size_t *ivl, size_t *ctl, size_t *tgl)
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

    *ivl = 0;
    *tgl = 0;
    *ctl = tmp;
    return ct;
}

static uint8_t *
unseal(const char *alg, EVP_PKEY *key,
       const uint8_t iv[], size_t ivl,
       const uint8_t ct[], size_t ctl,
       const uint8_t tg[], size_t tgl,
       size_t *ptl)
{
    uint8_t *pt = NULL;
    int tmp = 0;

    if (iv || ivl > 0 || tg || tgl > 0)
        return NULL;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: tmp = RSA_PKCS1_PADDING; break;
    case 1: tmp = RSA_PKCS1_OAEP_PADDING; break;
    default: return NULL;
    }

    pt = malloc((RSA_size(key->pkey.rsa) + 7) / 8);
    if (!pt)
        return NULL;

    tmp = RSA_private_decrypt(ctl, ct, pt, key->pkey.rsa, tmp);
    if (tmp <= 0) {
        memset(pt, 0, *ptl);
        free(pt);
        return NULL;
    }

    *ptl = tmp;
    return pt;
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
