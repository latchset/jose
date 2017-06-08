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

#include <openssl/rand.h>

#include <string.h>

#define NAMES "A128KW", "A192KW", "A256KW"

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
    const char *alg = NULL;
    json_int_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) < 0)
        return NULL;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: len = 16; break;
    case 1: len = 24; break;
    case 2: len = 32; break;
    default: return NULL;
    }

    return json_pack("{s:{s:s,s:I}}", "upd", "kty", "oct", "bytes", len);
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

    if (!type || strcmp(type, "oct") != 0)
        return NULL;

    switch (jose_b64_dec(json_object_get(jwk, "k"), NULL, 0)) {
    case 16: return "A128KW";
    case 24: return "A192KW";
    case 32: return "A256KW";
    default: return NULL;
    }
}

static const char *
alg_wrap_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: return "A128CBC-HS256";
    case 1: return "A192CBC-HS384";
    case 2: return "A256CBC-HS512";
    default: return NULL;
    }
}

static bool
alg_wrap_wrp(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
             json_t *rcp, const json_t *jwk, json_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ecc = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ctl = 0;
    int len = 0;

    if (!json_object_get(cek, "k") && !jose_jwk_gen(cfg, cek))
        return false;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return false;
    }

    uint8_t ky[EVP_CIPHER_key_length(cph)];
    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    uint8_t pt[KEYMAX];
    uint8_t ct[sizeof(pt) + EVP_CIPHER_block_size(cph) * 2];

    memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

    if (jose_b64_dec(json_object_get(jwk, "k"), NULL, 0) != sizeof(ky))
        goto egress;

    if (jose_b64_dec(json_object_get(jwk, "k"), ky, sizeof(ky)) != sizeof(ky))
        goto egress;

    ptl = jose_b64_dec(json_object_get(cek, "k"), NULL, 0);
    if (ptl > sizeof(pt))
        goto egress;

    if (jose_b64_dec(json_object_get(cek, "k"), pt, ptl) != ptl)
        goto egress;

    ecc = EVP_CIPHER_CTX_new();
    if (!ecc)
        goto egress;

    EVP_CIPHER_CTX_set_flags(ecc, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ecc, cph, NULL, ky, iv) <= 0)
        goto egress;

    if (EVP_EncryptUpdate(ecc, ct, &len, pt, ptl) <= 0)
        goto egress;
    ctl = len;

    if (EVP_EncryptFinal(ecc, &ct[len], &len) <= 0)
        goto egress;
    ctl += len;

    if (json_object_set_new(rcp, "encrypted_key", jose_b64_enc(ct, ctl)) < 0)
        goto egress;

    ret = add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);

egress:
    OPENSSL_cleanse(ky, sizeof(ky));
    OPENSSL_cleanse(pt, sizeof(pt));
    EVP_CIPHER_CTX_free(ecc);
    return ret;
}

static bool
alg_wrap_unw(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *rcp, const json_t *jwk, json_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ecc = NULL;
    bool ret = false;
    size_t ctl = 0;
    size_t ptl = 0;
    int len = 0;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_wrap(); break;
    case 1: cph = EVP_aes_192_wrap(); break;
    case 2: cph = EVP_aes_256_wrap(); break;
    default: return NULL;
    }

    uint8_t ky[EVP_CIPHER_key_length(cph)];
    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    uint8_t ct[KEYMAX + EVP_CIPHER_block_size(cph) * 2];
    uint8_t pt[sizeof(ct)];

    memset(iv, 0xA6, sizeof(iv));

    if (jose_b64_dec(json_object_get(jwk, "k"), NULL, 0) != sizeof(ky))
        goto egress;

    if (jose_b64_dec(json_object_get(jwk, "k"), ky, sizeof(ky)) != sizeof(ky))
        goto egress;

    ctl = jose_b64_dec(json_object_get(rcp, "encrypted_key"), NULL, 0);
    if (ctl > sizeof(ct))
        goto egress;

    if (jose_b64_dec(json_object_get(rcp, "encrypted_key"), ct, ctl) != ctl)
        goto egress;

    ecc = EVP_CIPHER_CTX_new();
    if (!ecc)
        goto egress;

    EVP_CIPHER_CTX_set_flags(ecc, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ecc, cph, NULL, ky, iv) <= 0)
        goto egress;

    if (EVP_DecryptUpdate(ecc, pt, &len, ct, ctl) <= 0)
        goto egress;
    ptl = len;

    if (EVP_DecryptFinal(ecc, &pt[len], &len) <= 0)
        goto egress;
    ptl += len;

    ret = json_object_set_new(cek, "k", jose_b64_enc(pt, ptl)) == 0;

egress:
    OPENSSL_cleanse(ky, sizeof(ky));
    OPENSSL_cleanse(pt, sizeof(pt));
    EVP_CIPHER_CTX_free(ecc);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_PREP,
        .prep.handles = jwk_prep_handles,
        .prep.execute = jwk_prep_execute,
    };

    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "A128KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "A192KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "A256KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        {}
    };

    jose_hook_jwk_push(&jwk);
    for (size_t i = 0; algs[i].name; i++)
        jose_hook_alg_push(&algs[i]);
}
