/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#define NAMES "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"

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

    uint8_t hsh[size];

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return false;

    for (uint32_t c = 0; c <= reps; c++) {
        uint32_t cnt = htobe32(c + 1);

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
    memset(hsh, 0, sizeof(hsh));
    EVP_MD_CTX_destroy(ctx);
    return ret;
}

static EVP_PKEY *
generate(const EC_KEY *rem)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *prm = NULL;
    EVP_PKEY *lcl = NULL;
    int nid = NID_undef;

    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(rem));
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
        clear_free(key, *len);
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
    case 1: grp = "P-256"; break;
    case 2: grp = "P-384"; break;
    case 3: grp = "P-521"; break;
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
     const char *alg, json_t *cek)
{
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    const char *enc = NULL;
    EVP_PKEY *rem = NULL;
    EVP_PKEY *lcl = NULL;
    uint8_t *ky = NULL;
    uint8_t *pu = NULL;
    uint8_t *pv = NULL;
    json_t *tmp = NULL;
    json_t *epk = NULL;
    json_t *hd = NULL;
    json_t *h = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t pul = 0;
    size_t pvl = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0:
        kyl = jose_b64_dlen(json_string_length(json_object_get(cek, "k")));
        break;
    case 1: kyl = 16; aes = "A128KW"; break;
    case 2: kyl = 24; aes = "A192KW"; break;
    case 3: kyl = 32; aes = "A256KW"; break;
    default: return false;
    }

    if (kyl == 0)
        return false;

    uint8_t dk[kyl];

    hd = jose_jwe_merge_header(jwe, rcp);
    if (!hd)
        goto egress;

    if (json_unpack(hd, "{s?s,s?s,s?s}", "apu", &apu,
                    "apv", &apv, "enc", &enc) == -1)
        goto egress;

    if (!aes && !enc)
        goto egress;

    rem = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!rem || EVP_PKEY_base_id(rem) != EVP_PKEY_EC)
        goto egress;

    lcl = generate(rem->pkey.ec);
    if (!lcl)
        goto egress;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        return false;

    epk = jose_openssl_jwk_from_EVP_PKEY(lcl);
    if (json_object_set_new(h, "epk", epk) == -1)
        goto egress;

    if (!jose_jwk_clean(epk))
        goto egress;

    ky = ecdh(lcl, rem, &kyl);
    if (!ky)
        goto egress;

    pu = jose_b64_decode_buf(apu, &pul);
    pv = jose_b64_decode_buf(apv, &pvl);
    if ((apu && !pu) || (apv && !pv))
        goto egress;

    if (!concatkdf(EVP_sha256(), dk, sizeof(dk), ky, kyl,
                   aes ? alg : enc, strlen(aes ? alg : enc),
                   pu ? pu : (uint8_t *) "", pul,
                   pv ? pv : (uint8_t *) "", pvl, NULL))
        goto egress;

    tmp = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(dk, sizeof(dk)));
    if (!tmp)
        goto egress;

    if (aes)
        ret = aeskw_sealer.seal(jwe, rcp, tmp, aes, cek);
    else
        ret = json_object_update(cek, tmp) == 0;

egress:
    memset(dk, 0, sizeof(dk));
    clear_free(ky, kyl);
    EVP_PKEY_free(lcl);
    EVP_PKEY_free(rem);
    json_decref(tmp);
    free(pu);
    free(pv);
    return ret;
}

static size_t
get_keyl(const json_t *jwe, const json_t *rcp)
{
    const char *enc = NULL;
    json_t *head = NULL;
    json_t *jwk = NULL;
    size_t len = 0;

    head = jose_jwe_merge_header(jwe, rcp);
    if (!head)
        goto egress;

    if (json_unpack(head, "{s:s}", "enc", &enc) == -1)
        goto egress;

    jwk = json_pack("{s:s}", "alg", enc);
    if (!jwk)
        goto egress;

    if (!jose_jwk_generate(jwk))
        goto egress;

    if (!json_is_string(json_object_get(jwk, "k")))
        goto egress;

    len = jose_b64_dlen(json_string_length(json_object_get(jwk, "k")));

egress:
    json_decref(head);
    json_decref(jwk);
    return len;
}

static bool
unseal(const json_t *jwe, const json_t *rcp, const json_t *jwk,
       const char *alg, json_t *cek)
{
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    const char *enc = NULL;
    EVP_PKEY *rem = NULL;
    EVP_PKEY *lcl = NULL;
    uint8_t *ky = NULL;
    uint8_t *pu = NULL;
    uint8_t *pv = NULL;
    json_t *tmp = NULL;
    json_t *epk = NULL;
    json_t *hd = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t pul = 0;
    size_t pvl = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: kyl = get_keyl(jwe, rcp); if (kyl == 0) return false; break;
    case 1: kyl = 16; aes = "A128KW"; break;
    case 2: kyl = 24; aes = "A192KW"; break;
    case 3: kyl = 32; aes = "A256KW"; break;
    default: return false;
    }

    uint8_t dk[kyl];

    hd = jose_jwe_merge_header(jwe, rcp);
    if (json_unpack(hd, "{s:o,s?s,s?s,s:s}", "epk", &epk, "apu", &apu,
                    "apv", &apv, "enc", &enc) == -1)
        goto egress;

    if (!aes && !enc)
        goto egress;

    lcl = jose_openssl_jwk_to_EVP_PKEY(jwk);
    rem = jose_openssl_jwk_to_EVP_PKEY(epk);
    pu = jose_b64_decode_buf(apu, &pul);
    pv = jose_b64_decode_buf(apv, &pvl);
    if (!lcl || !rem || (apu && !pu) || (apv && !pv) ||
        EVP_PKEY_base_id(lcl) != EVP_PKEY_EC ||
        EVP_PKEY_base_id(rem) != EVP_PKEY_EC)
        goto egress;

    ky = ecdh(lcl, rem, &kyl);
    if (!ky)
        goto egress;

    if (!concatkdf(EVP_sha256(), dk, sizeof(dk), ky, kyl,
                   aes ? alg : enc, strlen(aes ? alg : enc),
                   pu ? pu : (uint8_t *) "", pul,
                   pv ? pv : (uint8_t *) "", pvl, NULL))
        goto egress;

    tmp = json_pack("{s:s,s:o}", "kty", "oct", "k",
                    jose_b64_encode_json(dk, sizeof(dk)));
    if (!tmp)
        goto egress;

    if (aes)
        ret = aeskw_sealer.unseal(jwe, rcp, tmp, aes, cek);
    else
        ret = json_object_update_missing(cek, tmp) == 0;

egress:
    memset(dk, 0, sizeof(dk));
    clear_free(ky, kyl);
    EVP_PKEY_free(lcl);
    EVP_PKEY_free(rem);
    json_decref(tmp);
    json_decref(hd);
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
