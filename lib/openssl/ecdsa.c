/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/openssl.h>

#include <openssl/ecdsa.h>

#include <string.h>

#define NAMES "ES256", "ES384", "ES512"

static EC_KEY *
setup(const json_t *jwk, const char *alg, const char *prot, const char *payl,
      uint8_t hsh[], size_t *hl)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    const char *req = NULL;
    unsigned int ign = 0;
    EC_KEY *key = NULL;

    *hl = 0;

    key = jose_openssl_jwk_to_EC_KEY(jwk);
    if (!key)
        return NULL;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key))) {
    case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
    case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
    case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
    default: goto error;
    }

    if (strcmp(alg, req) != 0)
        goto error;

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto error;

    if (EVP_DigestInit(ctx, md) <= 0)
        goto error;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) prot, strlen(prot)) <= 0)
        goto error;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) ".", 1) <= 0)
        goto error;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) payl, strlen(payl)) <= 0)
        goto error;

    if (EVP_DigestFinal(ctx, hsh, &ign) > 0)
        *hl = EVP_MD_size(md);

error:
    EVP_MD_CTX_destroy(ctx);
    if (*hl == 0)
        EC_KEY_free(key);
    return *hl != 0 ? key : NULL;
}

static bool
resolve(json_t *jwk)
{
    const char *alg = NULL;
    const char *crv = NULL;
    const char *kty = NULL;
    const char *grp = NULL;
    json_t *upd = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?s}",
                    "kty", &kty, "alg", &alg, "crv", &crv) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: grp = "P-256"; break;
    case 1: grp = "P-384"; break;
    case 2: grp = "P-521"; break;
    default: return true;
    }

    if (!kty) {
        if (json_object_set_new(jwk, "kty", json_string("EC")) == -1)
            return false;
    } else if (strcmp(kty, "EC") != 0)
        return false;

    if (!crv) {
        if (json_object_set_new(jwk, "crv", json_string(grp)) == -1)
            return false;
    } else if (strcmp(crv, grp) != 0)
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
    const char *crv = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}",
                    "kty", &kty, "crv", &crv) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: return "ES256";
    case 1: return "ES384";
    case 2: return "ES512";
    default: return NULL;
    }
}

static bool
sign(json_t *sig, const json_t *jwk,
     const char *alg, const char *prot, const char *payl)
{
    uint8_t hsh[EVP_MAX_MD_SIZE];
    ECDSA_SIG *ecdsa = NULL;
    EC_KEY *key = NULL;
    bool ret = false;
    size_t hl = 0;

    key = setup(jwk, alg, prot, payl, hsh, &hl);
    if (!key)
        return false;

    uint8_t s[(EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8 * 2];

    ecdsa = ECDSA_do_sign(hsh, hl, key);
    if (!ecdsa)
        goto egress;

    if (!bn_encode(ecdsa->r, s, sizeof(s) / 2))
        goto egress;

    if (!bn_encode(ecdsa->s, &s[sizeof(s) / 2], sizeof(s) / 2))
        goto egress;

    ret = json_object_set_new(sig, "signature",
                              jose_b64_encode_json(s, sizeof(s))) == 0;

egress:
    ECDSA_SIG_free(ecdsa);
    EC_KEY_free(key);
    return ret;
}

static bool
verify(const json_t *sig, const json_t *jwk,
       const char *alg, const char *prot, const char *payl)
{
    uint8_t hsh[EVP_MAX_MD_SIZE];
    ECDSA_SIG ecdsa = {};
    EC_KEY *key = NULL;
    uint8_t *sg = NULL;
    bool ret = false;
    size_t hshl = 0;
    size_t sgl = 0;

    key = setup(jwk, alg, prot, payl, hsh, &hshl);
    if (!key)
        return false;

    sg = jose_b64_decode_json(json_object_get(sig, "signature"), &sgl);
    if (sig) {
        ecdsa.r = bn_decode(sg, sgl / 2);
        ecdsa.s = bn_decode(&sg[sgl / 2], sgl / 2);
        if (ecdsa.r && ecdsa.s)
            ret = ECDSA_do_verify(hsh, hshl, &ecdsa, key) == 1;
    }

    EC_KEY_free(key);
    BN_free(ecdsa.r);
    BN_free(ecdsa.s);
    free(sg);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *algs[] = { NAMES, NULL };

    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jws_signer_t signer = {
        .algs = algs,
        .suggest = suggest,
        .verify = verify,
        .sign = sign,
    };

    jose_jwk_register_resolver(&resolver);
    jose_jws_register_signer(&signer);
}
