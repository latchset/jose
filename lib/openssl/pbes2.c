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

#define NAMES "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"

static json_t *
pbkdf2(const char *alg, jose_cfg_t *cfg, const json_t *jwk, int iter,
       uint8_t st[], size_t stl)
{
    const EVP_MD *md = NULL;
    json_auto_t *key = NULL;
    json_t *cek = NULL;
    size_t kyl = 0;
    size_t dkl = 0;

    if (json_is_string(jwk)) {
        jwk = key = json_pack("{s:s,s:o}", "kty", "oct", "k",
                              jose_b64_enc(json_string_value(jwk),
                                           json_string_length(jwk)));
        if (!jwk)
            return NULL;
    }

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); dkl = 16; break;
    case 1: md = EVP_sha384(); dkl = 24; break;
    case 2: md = EVP_sha512(); dkl = 32; break;
    default: return NULL;
    }

    const size_t pfx = strlen(alg) + 1;
    uint8_t slt[pfx + stl];
    uint8_t dk[dkl];
    char ky[KEYMAX];

    memcpy(slt, alg, pfx);
    memcpy(&slt[pfx], st, stl);

    kyl = jose_b64_dec(json_object_get(jwk, "k"), NULL, 0);
    if (kyl > sizeof(ky))
        return NULL;

    if (jose_b64_dec(json_object_get(jwk, "k"), ky, sizeof(ky)) != kyl) {
        OPENSSL_cleanse(ky, sizeof(ky));
        return NULL;
    }

    if (PKCS5_PBKDF2_HMAC(ky, kyl, slt, sizeof(slt), iter, md, dkl, dk) > 0)
        cek = json_pack("{s:s,s:o}", "kty", "oct", "k", jose_b64_enc(dk, dkl));

    OPENSSL_cleanse(ky, sizeof(ky));
    OPENSSL_cleanse(dk, sizeof(dk));
    return cek;
}

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) < 0)
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
    size_t len = 0;

    if (json_is_object(jwk)) {
        const char *name = NULL;
        const char *type = NULL;

        if (json_unpack((json_t *) jwk, "{s?s,s?s}",
                        "alg", &name, "kty", &type) < 0)
            return NULL;

        if (name)
            return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

        if (!type || strcmp(type, "oct") != 0)
            return NULL;

        len = jose_b64_dec(json_object_get(jwk, "k"), NULL, 0);
        if (len == SIZE_MAX)
            return NULL;

        /* Defer to other algorithms if defined... */
        for (const jose_hook_alg_t *a = alg->next; a; a = a->next) {
            if (a->kind != JOSE_HOOK_ALG_KIND_WRAP)
                continue;
            if (a->wrap.alg == alg_wrap_alg)
                continue;
            if (a->wrap.alg(alg, cfg, jwk))
                return NULL;
        }
    } else if (json_is_string(jwk)) {
        len = json_string_length(jwk);
        if (len > 36)
            return "PBES2-HS512+A256KW";
        else if (len > 27)
            return "PBES2-HS384+A192KW";
        else
            return "PBES2-HS256+A128KW";
    }

    return NULL;
}

static const char *
alg_wrap_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    switch (str2enum (alg->name, NAMES, NULL)) {
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
    json_auto_t *key = NULL;
    json_auto_t *hdr = NULL;
    const char *aes = NULL;
    json_t *h = NULL;
    int p2c = 10000;
    size_t stl = 0;

    if (!json_object_get(cek, "k") && !jose_jwk_gen(cfg, cek))
        return false;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: aes = "A128KW"; stl = 16; break;
    case 1: aes = "A192KW"; stl = 24; break;
    case 2: aes = "A256KW"; stl = 32; break;
    default: return false;
    }

    uint8_t st[stl];

    if (RAND_bytes(st, stl) <= 0)
        return false;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        return false;

    hdr = jose_jwe_hdr(jwe, rcp);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s?i}", "p2c", &p2c) < 0)
        return false;

    if (!json_object_get(hdr, "p2c") &&
        json_object_set_new(h, "p2c", json_integer(p2c)) < 0)
        return false;

    if (p2c < 1000)
        return false;

    if (json_object_set_new(h, "p2s", jose_b64_enc(st, stl)) == -1)
        return false;

    key = pbkdf2(alg->name, cfg, jwk, p2c, st, stl);
    if (!key)
        return false;

    alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, aes);
    if (!alg)
        return false;

    return alg->wrap.wrp(alg, cfg, jwe, rcp, key, cek);
}

static bool
alg_wrap_unw(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *rcp, const json_t *jwk, json_t *cek)
{
    json_auto_t *key = NULL;
    json_auto_t *hdr = NULL;
    uint8_t st[KEYMAX] = {};
    const char *aes = NULL;
    json_int_t p2c = -1;
    size_t stl = 0;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: aes = "A128KW"; break;
    case 1: aes = "A192KW"; break;
    case 2: aes = "A256KW"; break;
    default: return false;
    }

    hdr = jose_jwe_hdr(jwe, rcp);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s:I}", "p2c", &p2c) == -1)
        return false;

    stl = jose_b64_dec(json_object_get(hdr, "p2s"), NULL, 0);
    if (stl < 8 || stl > sizeof(st))
        return false;

    if (jose_b64_dec(json_object_get(hdr, "p2s"), st, sizeof(st)) != stl)
        return false;

    key = pbkdf2(alg->name, cfg, jwk, p2c, st, stl);
    if (!key)
        return false;

    alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, aes);
    if (!alg)
        return false;

    return alg->wrap.unw(alg, cfg, jwe, rcp, key, cek);
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
          .name = "PBES2-HS256+A128KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "PBES2-HS384+A192KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "PBES2-HS512+A256KW",
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
