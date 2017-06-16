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
#include "../hooks.h"
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

#ifdef EVP_PKEY_CTX_set_rsa_oaep_md
#define NAMES "RSA1_5", "RSA-OAEP", "RSA-OAEP-256"
#define HAVE_OAEP
#else
#define NAMES "RSA1_5"
#define EVP_PKEY_CTX_set_rsa_oaep_md(cfg, md) (-1)
#endif

declare_cleanup(EVP_PKEY_CTX)
declare_cleanup(EVP_PKEY)

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return str2enum(alg, NAMES, NULL) != SIZE_MAX;
}

static json_t *
jwk_prep_execute(jose_cfg_t *cfg, const json_t *jwk)
{
    if (!jwk_prep_handles(cfg, jwk))
        return NULL;

    return json_pack("{s:{s:s}}", "upd", "kty", "RSA");
}

static const char *
alg_wrap_alg(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *name = NULL;
    const char *type = NULL;

    if (json_unpack((json_t *) jwk, "{s?s,s?s}",
                    "alg", &name, "kty", &type) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "RSA") != 0)
        return NULL;

#ifdef HAVE_OAEP
    return "RSA-OAEP";
#else
    return "RSA1_5";
#endif
}

static const char *
alg_wrap_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    size_t len = 0;

    len = jose_b64_dec(json_object_get(jwk, "n"), NULL, 0) * 8;

    if (len >= 15360)
        return "A256CBC-HS512";
    else if (len >= 7680)
        return "A192CBC-HS384";
    else
        return "A128CBC-HS256";
}

static bool
alg_wrap_wrp(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
             json_t *rcp, const json_t *jwk, json_t *cek)
{
    openssl_auto(EVP_PKEY_CTX) *epc = NULL;
    openssl_auto(EVP_PKEY) *key = NULL;
    const EVP_MD *md = NULL;
    const RSA *rsa = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ctl = 0;
    int tmp = 0;
    int pad = 0;

    if (!json_object_get(cek, "k") && !jose_jwk_gen(cfg, cek))
        return false;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      tmp = 11; md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(cfg, jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return false;

    ptl = jose_b64_dec(json_object_get(cek, "k"), NULL, 0);
    if (ptl == SIZE_MAX)
        return false;

    rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
        return false;

    if ((int) ptl >= RSA_size(rsa) - tmp)
        return false;

    epc = EVP_PKEY_CTX_new(key, NULL);
    if (!epc)
        return false;

    if (EVP_PKEY_encrypt_init(epc) <= 0)
        return false;

    if (EVP_PKEY_CTX_set_rsa_padding(epc, pad) <= 0)
        return false;

    if (pad == RSA_PKCS1_OAEP_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(epc, md) <= 0)
            return false;

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(epc, md) <= 0)
            return false;
    }

    pt = malloc(ptl);
    if (!pt)
        return false;

    if (jose_b64_dec(json_object_get(cek, "k"), pt, ptl) != ptl)
        goto egress;

    if (EVP_PKEY_encrypt(epc, NULL, &ctl, pt, ptl) <= 0)
        goto egress;

    ct = malloc(ctl);
    if (!ct)
        goto egress;

    if (EVP_PKEY_encrypt(epc, ct, &ctl, pt, ptl) <= 0)
        goto egress;

    if (json_object_set_new(rcp, "encrypted_key", jose_b64_enc(ct, ctl)) < 0)
        goto egress;

    ret = add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);

egress:
    if (pt) {
        OPENSSL_cleanse(pt, ptl);
        free(pt);
    }

    free(ct);
    return ret;
}

static bool
alg_wrap_unw(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *rcp, const json_t *jwk, json_t *cek)
{
    openssl_auto(EVP_PKEY_CTX) *epc = NULL;
    openssl_auto(EVP_PKEY) *key = NULL;
    const uint8_t *tt = NULL;
    const EVP_MD *md = NULL;
    uint8_t *ct = NULL;
    uint8_t *pt = NULL;
    uint8_t *rt = NULL;
    bool ret = false;
    size_t ctl = 0;
    size_t ptl = 0;
    size_t rtl = 0;
    size_t ttl = 0;
    int pad = 0;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(cfg, jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        goto egress;

    ctl = jose_b64_dec(json_object_get(rcp, "encrypted_key"), NULL, 0);
    if (ctl == SIZE_MAX)
        goto egress;

    ct = malloc(ctl);
    if (!ct)
        goto egress;

    if (jose_b64_dec(json_object_get(rcp, "encrypted_key"), ct, ctl) != ctl)
        goto egress;

    ptl = ctl;
    pt = malloc(ptl);
    if (!pt)
        goto egress;

    epc = EVP_PKEY_CTX_new(key, NULL);
    if (!epc)
        goto egress;

    if (EVP_PKEY_decrypt_init(epc) <= 0)
        goto egress;

    if (EVP_PKEY_CTX_set_rsa_padding(epc, pad) <= 0)
        goto egress;

    if (pad == RSA_PKCS1_OAEP_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(epc, md) <= 0)
            goto egress;

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(epc, md) <= 0)
            goto egress;
    }

    /* Handle MMA Attack as prescribed by RFC 3218, always generate a
     * random buffer of appropriate length so that the same operations
     * are performed whether decrypt succeeds or not, in an attempt to
     * foil timing attacks */
    rtl = ptl;
    rt = malloc(rtl);
    if (!rt)
        goto egress;
    if (RAND_bytes(rt, rtl) <= 0)
        goto egress;

    ret |= EVP_PKEY_decrypt(epc, pt, &ptl, ct, ctl) > 0;
    ttl = ret ? ptl : rtl;
    tt = ret ? pt : rt;
    ret |= pad == RSA_PKCS1_PADDING;

    if (json_object_set_new(cek, "k", jose_b64_enc(tt, ttl)) < 0)
        ret = false;

egress:
    if (pt) {
        OPENSSL_cleanse(pt, ptl);
        free(pt);
    }

    if (rt) {
        OPENSSL_cleanse(rt, rtl);
        free(rt);
    }

    free(ct);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_PREP,
        .prep.handles = jwk_prep_handles,
        .prep.execute = jwk_prep_execute
    };

    static jose_hook_alg_t alg[] = {
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "RSA1_5",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
#ifdef HAVE_OAEP
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "RSA-OAEP",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "RSA-OAEP-256",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
#endif
        {}
    };

    jose_hook_jwk_push(&jwk);

    for (size_t i = 0; alg[i].name; i++)
        jose_hook_alg_push(&alg[i]);
}
