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

#include <openssl/rsa.h>

#include <string.h>

#ifdef EVP_PKEY_CTX_set_rsa_oaep_md
#define NAMES "RSA1_5", "RSA-OAEP", "RSA-OAEP-256"
#else
#define NAMES "RSA1_5"
#define EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) (-1)
#endif

static const char *algs[] = { NAMES, NULL };

static bool
resolve(json_t *jwk)
{
    json_auto_t *upd = NULL;
    const char *kty = NULL;
    const char *alg = NULL;

    if (json_unpack(jwk, "{s?s,s?s}", "kty", &kty, "alg", &alg) == -1)
        return false;

    if (!algs[str2enum(alg, NAMES, NULL)])
        return true;

    if (!kty && json_object_set_new(jwk, "kty", json_string("RSA")) == -1)
        return false;
    if (kty && strcmp(kty, "RSA") != 0)
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

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    if (strcmp(kty, "RSA") != 0)
        return NULL;

    return "RSA1_5";
}

static bool
wrap(json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
     const char *alg)
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

    if (!json_object_get(cek, "k") && !jose_jwk_generate(cek))
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: pad = RSA_PKCS1_PADDING;      tmp = 11; md = EVP_sha1(); break;
    case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha1(); break;
    case 2: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; md = EVP_sha256(); break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        goto egress;

    pt = jose_b64_decode_json(json_object_get(cek, "k"), &ptl);
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
unwrap(const json_t *jwe, const json_t *jwk, const json_t *rcp,
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

    ct = jose_b64_decode_json(json_object_get(rcp, "encrypted_key"), &ctl);
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
    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jwe_wrapper_t wrapper = {
        .algs = algs,
        .suggest = suggest,
        .wrap = wrap,
        .unwrap = unwrap,
    };

    jose_jwk_register_resolver(&resolver);
    jose_jwe_register_wrapper(&wrapper);
}
