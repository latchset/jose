/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2026 Red Hat, Inc.
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
#include "../hooks.h"
#include <jose/b64.h>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

#include <string.h>

#define NAMES "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"

static bool
mlkem_available(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!ctx)
        return false;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) != SIZE_MAX;
}

static bool
jwk_prep_execute(jose_cfg_t *cfg, json_t *jwk)
{
    if (json_object_set_new(jwk, "kty", json_string("AKP")) < 0)
        return false;

    return true;
}

static bool
jwk_make_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s?s}", "kty", &kty, "alg", &alg) < 0)
        return false;

    if (strcmp(kty, "AKP") != 0)
        return false;

    return alg && str2enum(alg, NAMES, NULL) != SIZE_MAX;
}

static bool
jwk_make_execute(jose_cfg_t *cfg, json_t *jwk)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const char *alg = NULL;
    unsigned char *pub = NULL;
    unsigned char seed[64] = {};
    size_t pub_len = 0;
    bool ret = false;

    if (json_unpack(jwk, "{s:s}", "alg", &alg) < 0)
        return false;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx)
        return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto egress;

    {
        int retain = 1;
        OSSL_PARAM gen_params[] = {
            OSSL_PARAM_int(OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED, &retain),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_CTX_set_params(ctx, gen_params) <= 0)
            goto egress;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto egress;

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) <= 0)
        goto egress;

    pub = jose_malloc(pub_len);
    if (!pub)
        goto egress;

    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0)
        goto egress;

    {
        size_t seed_len = sizeof(seed);
        OSSL_PARAM seed_params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                    seed, sizeof(seed)),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_get_params(pkey, seed_params) <= 0)
            goto egress;
        seed_len = seed_params[0].return_size;
        if (seed_len != 64)
            goto egress;
    }

    if (json_object_set_new(jwk, "pub", jose_b64_enc(pub, pub_len)) < 0)
        goto egress;

    if (json_object_set_new(jwk, "priv", jose_b64_enc(seed, 64)) < 0)
        goto egress;

    ret = true;

egress:
    OPENSSL_cleanse(seed, sizeof(seed));
    jose_free(pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static EVP_PKEY *
jwk_to_pub_pkey(const json_t *jwk)
{
    const char *alg = NULL;
    const char *kty = NULL;
    unsigned char *pub = NULL;
    EVP_PKEY *pkey = NULL;
    size_t pub_len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "alg", &alg, "kty", &kty) < 0)
        return NULL;

    if (strcmp(kty, "AKP") != 0)
        return NULL;

    pub_len = jose_b64_dec(json_object_get(jwk, "pub"), NULL, 0);
    if (pub_len == SIZE_MAX || pub_len == 0)
        return NULL;

    pub = jose_malloc(pub_len);
    if (!pub)
        return NULL;

    if (jose_b64_dec(json_object_get(jwk, "pub"), pub, pub_len) != pub_len) {
        jose_free(pub);
        return NULL;
    }

    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, pub_len);
    jose_free(pub);
    return pkey;
}

static EVP_PKEY *
jwk_to_priv_pkey(const json_t *jwk)
{
    const char *alg = NULL;
    const char *kty = NULL;
    unsigned char *priv = NULL;
    EVP_PKEY *pkey = NULL;
    size_t priv_len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "alg", &alg, "kty", &kty) < 0)
        return NULL;

    if (strcmp(kty, "AKP") != 0)
        return NULL;

    priv_len = jose_b64_dec(json_object_get(jwk, "priv"), NULL, 0);
    if (priv_len == SIZE_MAX || priv_len == 0)
        return NULL;

    if (priv_len != 64)
        return NULL;

    priv = jose_malloc(priv_len);
    if (!priv)
        return NULL;

    if (jose_b64_dec(json_object_get(jwk, "priv"), priv, priv_len) != priv_len) {
        OPENSSL_cleanse(priv, priv_len);
        jose_free(priv);
        return NULL;
    }

    {
        EVP_PKEY_CTX *ictx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
        if (!ictx) {
            OPENSSL_cleanse(priv, priv_len);
            jose_free(priv);
            return NULL;
        }

        OSSL_PARAM import_params[] = {
            OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                    priv, priv_len),
            OSSL_PARAM_END
        };
        if (EVP_PKEY_fromdata_init(ictx) <= 0 ||
            EVP_PKEY_fromdata(ictx, &pkey, EVP_PKEY_KEYPAIR,
                              import_params) <= 0) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        EVP_PKEY_CTX_free(ictx);
    }

    OPENSSL_cleanse(priv, priv_len);
    jose_free(priv);
    return pkey;
}

static json_t *
alg_kem_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
            const json_t *pub)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ct = NULL;
    unsigned char *ss = NULL;
    size_t ct_len = 0;
    size_t ss_len = 0;
    json_t *result = NULL;

    pkey = jwk_to_pub_pkey(pub);
    if (!pkey)
        return NULL;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
        goto egress;

    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0)
        goto egress;

    ct = jose_malloc(ct_len);
    ss = jose_malloc(ss_len);
    if (!ct || !ss)
        goto egress;

    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0)
        goto egress;

    {
        json_auto_t *ct_b64 = jose_b64_enc(ct, ct_len);
        json_auto_t *ss_b64 = jose_b64_enc(ss, ss_len);
        if (ct_b64 && ss_b64)
            result = json_pack("{s:O,s:{s:s,s:O}}",
                               "ct", ct_b64,
                               "ss", "kty", "oct", "k", ss_b64);
    }

egress:
    if (ss) {
        OPENSSL_cleanse(ss, ss_len);
        jose_free(ss);
    }
    jose_free(ct);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

static json_t *
alg_kem_dec(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
            const json_t *prv, const json_t *ct)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ct_buf = NULL;
    unsigned char *ss = NULL;
    size_t ct_len = 0;
    size_t ss_len = 0;
    json_t *result = NULL;

    if (!json_is_string(ct))
        return NULL;

    pkey = jwk_to_priv_pkey(prv);
    if (!pkey)
        return NULL;

    ct_len = jose_b64_dec(ct, NULL, 0);
    if (ct_len == SIZE_MAX || ct_len == 0)
        goto egress;

    ct_buf = jose_malloc(ct_len);
    if (!ct_buf)
        goto egress;

    if (jose_b64_dec(ct, ct_buf, ct_len) != ct_len)
        goto egress;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto egress;

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
        goto egress;

    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct_buf, ct_len) <= 0)
        goto egress;

    ss = jose_malloc(ss_len);
    if (!ss)
        goto egress;

    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct_buf, ct_len) <= 0)
        goto egress;

    {
        json_auto_t *ss_b64 = jose_b64_enc(ss, ss_len);
        if (ss_b64)
            result = json_pack("{s:s,s:O}", "kty", "oct", "k", ss_b64);
    }

egress:
    if (ss) {
        OPENSSL_cleanse(ss, ss_len);
        jose_free(ss);
    }
    jose_free(ct_buf);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

static const char *
alg_kem_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
            const json_t *jwk)
{
    return NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwks[] = {
        { .kind = JOSE_HOOK_JWK_KIND_PREP,
          .prep.handles = jwk_prep_handles,
          .prep.execute = jwk_prep_execute },
        { .kind = JOSE_HOOK_JWK_KIND_MAKE,
          .make.handles = jwk_make_handles,
          .make.execute = jwk_make_execute },
        {}
    };

    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_KEM,
          .name = "ML-KEM-512",
          .kem.prm = "deriveKey",
          .kem.sug = alg_kem_sug,
          .kem.enc = alg_kem_enc,
          .kem.dec = alg_kem_dec },
        { .kind = JOSE_HOOK_ALG_KIND_KEM,
          .name = "ML-KEM-768",
          .kem.prm = "deriveKey",
          .kem.sug = alg_kem_sug,
          .kem.enc = alg_kem_enc,
          .kem.dec = alg_kem_dec },
        { .kind = JOSE_HOOK_ALG_KIND_KEM,
          .name = "ML-KEM-1024",
          .kem.prm = "deriveKey",
          .kem.sug = alg_kem_sug,
          .kem.enc = alg_kem_enc,
          .kem.dec = alg_kem_dec },
        {}
    };

    if (!mlkem_available())
        return;

    for (size_t i = 0; jwks[i].kind != JOSE_HOOK_JWK_KIND_NONE; i++)
        jose_hook_jwk_push(&jwks[i]);

    for (size_t i = 0; algs[i].name; i++)
        jose_hook_alg_push(&algs[i]);
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */
