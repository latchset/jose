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
#include <jose/jws.h>
#include <jose/openssl.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"

static bool
resolve(json_t *jwk)
{
    json_auto_t *upd = NULL;
    const char *alg = NULL;
    const char *kty = NULL;

    if (json_unpack(jwk, "{s?s,s?s}", "kty", &kty, "alg", &alg) == -1)
        return false;

    if (str2enum(alg, NAMES, NULL) >= 6)
        return true;

    if (!kty && json_object_set_new(jwk, "kty", json_string("RSA")) == -1)
        return false;
    if (kty && strcmp(kty, "RSA") != 0)
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "sig", "key_ops",
                    "sign", "verify");
    if (!upd)
        return false;

    return json_object_update_missing(jwk, upd) == 0;
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

static bool
sign(json_t *sig, const json_t *jwk,
     const char *alg, const char *prot, const char *payl)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *sg = NULL;
    bool ret = false;
    size_t sgl = 0;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        goto egress;

    /* Don't use small keys. RFC 7518 3.3 */
    if (RSA_size(key->pkey.rsa) < 2048 / 8)
        goto egress;

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto egress;

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, key) < 0)
        goto egress;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto egress;

    if (EVP_DigestSignUpdate(ctx, prot, strlen(prot)) < 0)
        goto egress;

    if (EVP_DigestSignUpdate(ctx, ".", 1) < 0)
        goto egress;

    if (EVP_DigestSignUpdate(ctx, payl, strlen(payl)) < 0)
        goto egress;

    if (EVP_DigestSignFinal(ctx, NULL, &sgl) < 0)
        goto egress;

    sg = malloc(sgl);
    if (!sg)
        goto egress;

    if (EVP_DigestSignFinal(ctx, sg, &sgl) < 0)
        goto egress;

    ret = json_object_set_new(sig, "signature",
                              jose_b64_encode_json(sg, sgl)) == 0;

egress:
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
    free(sg);
    return ret;
}

static bool
verify(const json_t *sig, const json_t *jwk,
       const char *alg, const char *prot, const char *payl)
{
    jose_buf_auto_t *sgn = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    bool ret = false;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        goto egress;

    /* Don't use small keys. RFC 7518 3.3 */
    if (RSA_size(key->pkey.rsa) < 2048 / 8)
        goto egress;

    sgn = jose_b64_decode_json(json_object_get(sig, "signature"));
    if (!sgn)
        goto egress;

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

    ret = EVP_DigestVerifyFinal(ctx, sgn->data, sgn->size) == 1;

egress:
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
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
