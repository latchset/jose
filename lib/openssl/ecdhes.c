/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#define NAMES "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"

extern jose_jwe_sealer_t aeskw_sealer;

static bool
concatkdf(const EVP_MD *md, uint8_t dk[], size_t dkl,
          const uint8_t z[], size_t zl, ...)
{
    EVP_MD_CTX *ctx = NULL;
    bool ret = false;
    size_t size = 0;
    size_t reps = 0;
    size_t left = 0;
    va_list ap;

    size = EVP_MD_size(md);
    reps = dkl / size;
    left = dkl % size;

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return false;

    for (uint32_t c = 0; c <= reps; c++) {
        uint32_t cnt = htobe32(c + 1);
        uint8_t hsh[size];

        if (EVP_DigestInit_ex(ctx, md, NULL) <= 0)
            goto egress;

        if (EVP_DigestUpdate(ctx, &cnt, sizeof(cnt)) <= 0)
            goto egress;

        if (EVP_DigestUpdate(ctx, z, zl) <= 0)
            goto egress;

        va_start(ap, zl);
        for (void *b = va_arg(ap, void *); b; b = va_arg(ap, void *)) {
            size_t l = va_arg(ap, size_t);
            uint32_t e = htobe32(l);

            if (EVP_DigestUpdate(ctx, &e, sizeof(e)) <= 0) {
                va_end(ap);
                goto egress;
            }

            if (EVP_DigestUpdate(ctx, b, l) <= 0) {
                va_end(ap);
                goto egress;
            }
        }
        va_end(ap);

        if (EVP_DigestUpdate(ctx, &(uint32_t) { htobe32(dkl * 8) }, 4) <= 0) {
            va_end(ap);
            goto egress;
        }

        if (EVP_DigestFinal_ex(ctx, hsh, NULL) <= 0)
            goto egress;

        memcpy(&dk[c * size], hsh, c == reps ? left : size);
    }

    ret = true;

egress:
    EVP_MD_CTX_destroy(ctx);
    return ret;
}

static EVP_PKEY *
generate(const EVP_PKEY *rem)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *prm = NULL;
    EVP_PKEY *lcl = NULL;
    int nid = NID_undef;

    if (EVP_PKEY_base_id(rem) != EVP_PKEY_EC)
        return NULL;

    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(rem->pkey.ec));
    if (nid == NID_undef)
        return NULL;

    /* Create the key generation parameters. */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx)
        goto egress;

    if (EVP_PKEY_paramgen_init(pctx) <= 0)
        goto egress;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0)
        goto egress;

    if (!EVP_PKEY_paramgen(pctx, &prm))
        goto egress;

    /* Generate the ephemeral key. */
    kctx = EVP_PKEY_CTX_new(prm, NULL);
    if (!kctx)
        goto egress;

    if (EVP_PKEY_keygen_init(kctx) <= 0)
        goto egress;

    if (EVP_PKEY_keygen(kctx, &lcl) <= 0)
        goto egress;

egress:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(prm);
    return lcl;
}

static uint8_t *
ecdh(EVP_PKEY *lcl, EVP_PKEY *rem, size_t *len)
{
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *key = NULL;

    ctx = EVP_PKEY_CTX_new(lcl, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto egress;

    if (EVP_PKEY_derive_set_peer(ctx, rem) <= 0)
        goto egress;

    if (EVP_PKEY_derive(ctx, NULL, len) <= 0)
        goto egress;

    key = malloc(*len);
    if (!key)
        goto egress;

    if (EVP_PKEY_derive(ctx, key, len) <= 0) {
        free(key);
        key = NULL;
    }

egress:
    EVP_PKEY_CTX_free(ctx);
    return key;
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
    const char *crv = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}",
                    "kty", &kty, "crv", &crv) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: return "ECDH-ES+A128KW";
    case 1: return "ECDH-ES+A192KW";
    case 2: return "ECDH-ES+A256KW";
    default: return NULL;
    }
}

static bool
seal(const json_t *jwe, json_t *rcp, const json_t *jwk,
     const char *alg, const json_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    EVP_PKEY *rem = NULL;
    EVP_PKEY *lcl = NULL;
    uint8_t *ky = NULL;
    uint8_t *pu = NULL;
    uint8_t *pv = NULL;
    json_t *tmp = NULL;
    json_t *epk = NULL;
    json_t *h = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t pul = 0;
    size_t pvl = 0;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        return false;

    if (json_unpack(h, "{s?s,s?s}", "apu", &apu, "apv", &apv) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); aes = "A128KW"; break;
    case 1: cph = EVP_aes_192_wrap(); aes = "A192KW"; break;
    case 2: cph = EVP_aes_256_wrap(); aes = "A256KW"; break;
    default: return false;
    }

    uint8_t dk[EVP_CIPHER_key_length(cph)];

    rem = jose_openssl_jwk_to_key(jwk, JOSE_JWK_TYPE_EC);
    if (!rem)
        goto egress;

    lcl = generate(rem);
    if (!lcl)
        goto egress;

    ky = ecdh(lcl, rem, &kyl);
    if (!ky)
        goto egress;

    pu = jose_b64_decode_buf(apu, &pul);
    pv = jose_b64_decode_buf(apv, &pvl);
    if ((apu && !pu) || (apv && !pv))
        goto egress;

    if (!concatkdf(EVP_sha256(), dk, sizeof(dk), ky, kyl, alg, strlen(alg),
                   pu ? pu : (uint8_t *) "", pul,
                   pv ? pv : (uint8_t *) "", pvl, NULL))
        goto egress;

    tmp = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(dk, sizeof(dk)));
    if (!tmp)
        goto egress;

    if (!aeskw_sealer.seal(jwe, rcp, tmp, aes, cek))
        goto egress;

    if (json_object_set_new(h, "epk",
                epk = jose_openssl_jwk_from_key(lcl, JOSE_JWK_TYPE_EC)) == -1)
        goto egress;

    ret = jose_jwk_clean(epk, JOSE_JWK_TYPE_EC);

egress:
    EVP_PKEY_free(lcl);
    EVP_PKEY_free(rem);
    json_decref(tmp);
    free(ky);
    free(pu);
    free(pv);
    return ret;
}

static bool
unseal(const json_t *jwe, const json_t *rcp, const json_t *jwk,
       const char *alg, json_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    EVP_PKEY *rem = NULL;
    EVP_PKEY *lcl = NULL;
    uint8_t *ky = NULL;
    uint8_t *pu = NULL;
    uint8_t *pv = NULL;
    json_t *tmp = NULL;
    json_t *epk = NULL;
    json_t *p = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t pul = 0;
    size_t pvl = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); aes = "A128KW"; break;
    case 1: cph = EVP_aes_192_wrap(); aes = "A192KW"; break;
    case 2: cph = EVP_aes_256_wrap(); aes = "A256KW"; break;
    default: return false;
    }

    uint8_t dk[EVP_CIPHER_key_length(cph)];

    p = json_object_get(jwe, "protected");
    if (p) {
        p = jose_b64_decode_json_load(p);
        if (!p)
            return NULL;
    }

    /* Load "epk" header parameter (required). */
    if (json_unpack(p, "{s:o}", "epk", &epk) == -1 &&
        json_unpack((json_t *) jwe, "{s:{s:o}}",
                    "unprotected", "epk", &epk) == -1 &&
        json_unpack((json_t *) rcp, "{s:{s:o}}", "header", "epk", &epk) == -1)
        goto egress;

    /* Load "apu" header parameter (optional). */
    if (json_unpack(p, "{s?s}", "apu", &apu) == -1)
        goto egress;
    if (!apu && json_unpack((json_t *) jwe, "{s?{s?s}}",
                            "unprotected", "apu", &apu) == -1)
        goto egress;
    if (!apu && json_unpack((json_t *) rcp, "{s?{s?s}}",
                            "header", "apu", &apu) == -1)
        goto egress;

    /* Load "apv" header parameter (optional). */
    if (json_unpack(p, "{s?s}", "apv", &apv) == -1)
        goto egress;
    if (!apv && json_unpack((json_t *) jwe, "{s?{s?s}}",
                            "unprotected", "apv", &apv) == -1)
        goto egress;
    if (!apv && json_unpack((json_t *) rcp, "{s?{s?s}}",
                            "header", "apv", &apv) == -1)
        goto egress;

    lcl = jose_openssl_jwk_to_key(jwk, JOSE_JWK_TYPE_EC);
    rem = jose_openssl_jwk_to_key(epk, JOSE_JWK_TYPE_EC);
    pu = jose_b64_decode_buf(apu, &pul);
    pv = jose_b64_decode_buf(apv, &pvl);
    if (!lcl || !rem || (apu && !pu) || (apv && !pv))
        goto egress;

    ky = ecdh(lcl, rem, &kyl);
    if (!ky)
        goto egress;

    if (!concatkdf(EVP_sha256(), dk, sizeof(dk), ky, kyl, alg, strlen(alg),
                   pu ? pu : (uint8_t *) "", pul,
                   pv ? pv : (uint8_t *) "", pvl, NULL))
        goto egress;

    tmp = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(dk, sizeof(dk)));
    if (!tmp)
        goto egress;

    ret = aeskw_sealer.unseal(jwe, rcp, tmp, aes, cek);

egress:
    EVP_PKEY_free(lcl);
    EVP_PKEY_free(rem);
    json_decref(tmp);
    json_decref(p);
    free(ky);
    free(pu);
    free(pv);
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
