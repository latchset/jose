/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string.h>

#define NAMES "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"

extern jose_jwe_wrapper_t aeskw_wrapper;

static json_t *
exchange(const json_t *prv, const json_t *pub)
{
    const EC_GROUP *grp = NULL;
    json_t *key = NULL;
    EC_KEY *lcl = NULL;
    EC_KEY *rem = NULL;
    BN_CTX *bnc = NULL;
    EC_POINT *p = NULL;

    bnc = BN_CTX_new();
    if (!bnc)
        return NULL;

    lcl = jose_openssl_jwk_to_EC_KEY(prv);
    if (!lcl)
        goto egress;

    rem = jose_openssl_jwk_to_EC_KEY(pub);
    if (!rem)
        goto egress;

    grp = EC_KEY_get0_group(lcl);
    if (EC_GROUP_cmp(grp, EC_KEY_get0_group(rem), bnc) != 0)
        goto egress;

    p = EC_POINT_new(grp);
    if (!p)
        goto egress;

    if (EC_POINT_mul(grp, p, NULL, EC_KEY_get0_public_key(rem),
                     EC_KEY_get0_private_key(lcl), bnc) <= 0)
        goto egress;

    key = jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(rem), p, NULL);

egress:
    EC_POINT_free(p);
    EC_KEY_free(lcl);
    EC_KEY_free(rem);
    BN_CTX_free(bnc);
    return key;
}

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

static bool
resolve(json_t *jwk)
{
    const char *alg = NULL;
    const char *crv = NULL;
    const char *kty = NULL;
    const char *grp = NULL;
    json_auto_t *upd = NULL;

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

    if (!kty && json_object_set_new(jwk, "kty", json_string("EC")) == -1)
        return false;
    if (kty && strcmp(kty, "EC") != 0)
        return false;

    if (!crv && json_object_set_new(jwk, "crv", json_string(grp)) == -1)
        return false;
    if (crv && strcmp(crv, grp) != 0)
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops",
                    "wrapKey", "unwrapKey");
    if (!upd)
        return false;

    return json_object_update_missing(jwk, upd) == 0;
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
wrap(json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
     const char *alg)
{
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    const char *enc = NULL;
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

    if (json_object_get(cek, "k")) {
        if (strcmp(alg, "ECDH-ES") == 0)
            return false;
    } else if (!jose_jwk_generate(cek)) {
        return false;
    }

    switch (str2enum(alg, NAMES, NULL)) {
    case 0:
        kyl = jose_b64_dlen(json_string_length(json_object_get(cek, "k")));
        if (kyl == 0)
            return false;
        break;
    case 1: kyl = 16; aes = "A128KW"; break;
    case 2: kyl = 24; aes = "A192KW"; break;
    case 3: kyl = 32; aes = "A256KW"; break;
    default: return false;
    }

    uint8_t dk[kyl];

    hd = jose_jwe_merge_header(jwe, rcp);
    if (!hd)
        goto egress;

    if (json_unpack(hd, "{s?s,s?s,s?s}", "apu", &apu,
                    "apv", &apv, "enc", &enc) == -1)
        goto egress;

    if (!aes && !enc)
        goto egress;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        goto egress;

    epk = json_pack("{s:s,s:O}", "kty", "EC", "crv",
                    json_object_get(jwk, "crv"));
    if (!epk)
        goto egress;

    if (json_object_set_new(h, "epk", epk) == -1)
        goto egress;

    if (!jose_jwk_generate(epk))
        goto egress;

    tmp = exchange(epk, jwk);
    if (!tmp)
        goto egress;

    if (!jose_jwk_clean(epk))
        goto egress;

    ky = jose_b64_decode_json(json_object_get(tmp, "x"), &kyl);
    json_decref(tmp);
    if (!ky)
        goto egress;

    pu = jose_b64_decode(apu, &pul);
    pv = jose_b64_decode(apv, &pvl);
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
        ret = aeskw_wrapper.wrap(jwe, cek, tmp, rcp, aes);
    else
        ret = json_object_update(cek, tmp) == 0;

egress:
    memset(dk, 0, sizeof(dk));
    clear_free(ky, kyl);
    json_decref(tmp);
    json_decref(hd);
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
unwrap(const json_t *jwe, const json_t *jwk, const json_t *rcp,
       const char *alg, json_t *cek)
{
    const char *apu = NULL;
    const char *apv = NULL;
    const char *aes = NULL;
    const char *enc = NULL;
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

    pu = jose_b64_decode(apu, &pul);
    pv = jose_b64_decode(apv, &pvl);
    if ((apu && !pu) || (apv && !pv))
        goto egress;

    /* If the JWK has a private key, perform the normal exchange. */
    if (json_object_get(jwk, "d"))
        tmp = exchange(jwk, epk);

    /* Otherwise, allow external exchanges. */
    else if (json_equal(json_object_get(jwk, "crv"),
                        json_object_get(epk, "crv")))
        tmp = json_deep_copy(jwk);

    ky = jose_b64_decode_json(json_object_get(tmp, "x"), &kyl);
    json_decref(tmp);
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
        ret = aeskw_wrapper.unwrap(jwe, tmp, rcp, aes, cek);
    else
        ret = json_object_update_missing(cek, tmp) == 0;

egress:
    memset(dk, 0, sizeof(dk));
    clear_free(ky, kyl);
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

    static jose_jwk_exchanger_t exchanger = {
        .exchange = exchange
    };

    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jwe_wrapper_t wrapper = {
        .algs = algs,
        .suggest = suggest,
        .wrap = wrap,
        .unwrap = unwrap,
    };

    jose_jwk_register_exchanger(&exchanger);
    jose_jwk_register_resolver(&resolver);
    jose_jwe_register_wrapper(&wrapper);
}
