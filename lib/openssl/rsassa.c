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
#include <jose/hooks.h>
#include <jose/openssl.h>

#include <openssl/sha.h>

#include <string.h>

#define NAMES "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"

declare_cleanup(EVP_MD_CTX)
declare_cleanup(EVP_PKEY)

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
    openssl_auto(EVP_MD_CTX) *ctx = NULL;
    openssl_auto(EVP_PKEY) *key = NULL;
    jose_buf_auto_t *sg = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    const RSA *rsa = NULL;
    size_t sgl = 0;
    int slen = 0;
    int pad = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; slen = -1; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; slen = -1; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; slen = -1; break;
    default: return false;
    }

    key = jose_openssl_jwk_to_EVP_PKEY(jwk);
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return false;

    /* Don't use small keys. RFC 7518 3.3 */
    rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
        return false;
    if (RSA_size(rsa) < 2048 / 8)
        return false;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, key) < 0)
        return false;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        return false;

    if (slen != 0) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, slen) < 0)
            return false;
    }

    if (EVP_DigestSignUpdate(ctx, prot, strlen(prot)) < 0)
        return false;

    if (EVP_DigestSignUpdate(ctx, ".", 1) < 0)
        return false;

    if (EVP_DigestSignUpdate(ctx, payl, strlen(payl)) < 0)
        return false;

    if (EVP_DigestSignFinal(ctx, NULL, &sgl) < 0)
        return false;

    sg = jose_buf(sgl, JOSE_BUF_FLAG_WIPE);
    if (!sg)
        return false;

    if (EVP_DigestSignFinal(ctx, sg->data, &sg->size) < 0)
        return false;

    return json_object_set_new(sig, "signature",
                               jose_b64_encode_json(sg->data, sg->size)) == 0;
}

static bool
verify(const json_t *sig, const json_t *jwk,
       const char *alg, const char *prot, const char *payl)
{
    openssl_auto(EVP_MD_CTX) *ctx = NULL;
    openssl_auto(EVP_PKEY) *key = NULL;
    jose_buf_auto_t *sgn = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    const RSA *rsa = NULL;
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
        return false;

    /* Don't use small keys. RFC 7518 3.3 */
    rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa)
        return false;
    if (RSA_size(rsa) < 2048 / 8)
        return false;

    sgn = jose_b64_decode_json(json_object_get(sig, "signature"));
    if (!sgn)
        return false;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, key) < 0)
        return false;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        return false;

    if (EVP_DigestVerifyUpdate(ctx, prot, strlen(prot)) < 0)
        return false;

    if (EVP_DigestVerifyUpdate(ctx, ".", 1) < 0)
        return false;

    if (EVP_DigestVerifyUpdate(ctx, payl, strlen(payl)) < 0)
        return false;

    return EVP_DigestVerifyFinal(ctx, sgn->data, sgn->size) == 1;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jws_signer_t signers[] = {
        { NULL, "RS256", suggest, sign, verify },
        { NULL, "RS384", suggest, sign, verify },
        { NULL, "RS512", suggest, sign, verify },
        { NULL, "PS256", suggest, sign, verify },
        { NULL, "PS384", suggest, sign, verify },
        { NULL, "PS512", suggest, sign, verify },
        {}
    };

    jose_jwk_register_resolver(&resolver);

    for (size_t i = 0; signers[i].alg; i++)
        jose_jws_register_signer(&signers[i]);
}
