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

#define _GNU_SOURCE
#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include "../hooks.h"
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

#define NAMES "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"

#include <assert.h>

static uint32_t
h2be32(uint32_t x)
{
    union swap {
        uint32_t i;
        uint8_t  b[8];
    } y;

    y.b[0] = x >> 0x18;
    y.b[1] = x >> 0x10;
    y.b[2] = x >> 0x08;
    y.b[3] = x >> 0x00;

    return y.i;
}

static bool
concatkdf(const jose_hook_alg_t *alg, jose_cfg_t *cfg, uint8_t dk[], size_t dkl,
          const uint8_t z[], size_t zl, ...)
{
    jose_io_auto_t *b = NULL;
    uint8_t hsh[alg->hash.size];
    size_t hshl = sizeof(hsh);
    size_t reps = 0;
    size_t left = 0;

    reps = dkl / sizeof(hsh);
    left = dkl % sizeof(hsh);

    b = jose_io_buffer(cfg, &hsh, &hshl);
    if (!b)
        return false;

    for (uint32_t c = 0; c <= reps; c++) {
        uint32_t cnt = h2be32(c + 1);
        jose_io_auto_t *h = NULL;
        va_list ap;

        h = alg->hash.hsh(alg, cfg, b);
        if (!h)
            return false;

        if (!h->feed(h, &cnt, sizeof(cnt)))
            return false;

        if (!h->feed(h, z, zl))
            return false;

        va_start(ap, zl);
        for (void *a = va_arg(ap, void *); a; a = va_arg(ap, void *)) {
            size_t l = va_arg(ap, size_t);
            uint32_t e = h2be32(l);

            if (!h->feed(h, &e, sizeof(e))) {
                va_end(ap);
                return false;
            }

            if (!h->feed(h, a, l)) {
                va_end(ap);
                return false;
            }
        }
        va_end(ap);

        if (!h->feed(h, &(uint32_t) { h2be32(dkl * 8) }, 4))
            return false;

        if (!h->done(h))
            return false;

        assert(hshl == alg->hash.size);

        memcpy(&dk[c * hshl], hsh, c == reps ? left : hshl);
        OPENSSL_cleanse(hsh, sizeof(hsh));
        hshl = 0;
    }

    return true;
}

static size_t
encr_alg_keylen(jose_cfg_t *cfg, const char *enc)
{
    json_auto_t *tmpl = NULL;

    if (!jose_hook_alg_find(JOSE_HOOK_ALG_KIND_ENCR, enc))
        return SIZE_MAX;

    tmpl = json_pack("{s:s}", "alg", enc);
    if (!tmpl)
        return SIZE_MAX;

    for (const jose_hook_jwk_t *j = jose_hook_jwk_list(); j; j = j->next) {
        const char *kty = NULL;
        json_int_t len = 0;

        if (j->kind != JOSE_HOOK_JWK_KIND_PREP)
            continue;

        if (!j->prep.handles(cfg, tmpl))
            continue;

        if (!j->prep.execute(cfg, tmpl))
            return SIZE_MAX;

        if (json_unpack(tmpl, "{s:s,s:I}", "kty", &kty, "bytes", &len) < 0)
            return SIZE_MAX;

        if (strcmp(kty, "oct") != 0)
            return SIZE_MAX;

        return len;
    }

    return SIZE_MAX;
}

static size_t
decode(const json_t *obj, const char *name, uint8_t *buf, size_t len)
{
    const char *tmp = NULL;
    size_t tmpl = 0;
    size_t dlen = 0;

    if (json_unpack((json_t *) obj, "{s?s%}", name, &tmp, &tmpl) < 0)
        return SIZE_MAX;

    if (!tmp)
        return 0;

    dlen = jose_b64_dec_buf(tmp, tmpl, NULL, 0);
    if (dlen > len)
        return dlen;

    return jose_b64_dec_buf(tmp, tmpl, buf, len);
}

static json_t *
derive(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
       json_t *hdr, json_t *cek, const json_t *key)
{
    const jose_hook_alg_t *halg = NULL;
    const char *name = alg->name;
    uint8_t pu[KEYMAX] = {};
    uint8_t pv[KEYMAX] = {};
    uint8_t dk[KEYMAX] = {};
    uint8_t ky[KEYMAX] = {};
    const char *enc = NULL;
    json_t *out = NULL;
    size_t dkl = 0;
    size_t pul = 0;
    size_t pvl = 0;
    size_t kyl = 0;

    halg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, "S256");
    if (!halg)
        goto egress;

    if (json_unpack(hdr, "{s?s}", "enc", &enc) < 0)
        goto egress;

    if (!enc && json_unpack(cek, "{s:s}", "alg", &enc) < 0)
        goto egress;

    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: dkl = encr_alg_keylen(cfg, enc); name = enc; break;
    case 1: dkl = 16; break;
    case 2: dkl = 24; break;
    case 3: dkl = 32; break;
    default:
        goto egress;
    }

    if (dkl < 16 || dkl > sizeof(dk))
        goto egress;

    pul = decode(hdr, "apu", pu, sizeof(pu));
    if (pul > sizeof(pu))
        goto egress;

    pvl = decode(hdr, "apv", pv, sizeof(pv));
    if (pvl > sizeof(pv))
        goto egress;

    kyl = decode(key, "x", ky, sizeof(ky));
    if (kyl > sizeof(ky))
        goto egress;

    if (!concatkdf(halg, cfg,
                   dk, dkl,
                   ky, kyl,
                   name, strlen(name),
                   pu, pul,
                   pv, pvl,
                   NULL))
        goto egress;

    out = json_pack("{s:s,s:s,s:o}", "kty", "oct", "alg", enc,
                    "k", jose_b64_enc(dk, dkl));

egress:
    OPENSSL_cleanse(ky, sizeof(ky));
    OPENSSL_cleanse(pu, sizeof(pu));
    OPENSSL_cleanse(pv, sizeof(pv));
    OPENSSL_cleanse(dk, sizeof(dk));
    return out;
}

static const char *
alg2crv(const char *alg)
{
    switch (str2enum(alg, NAMES, NULL)) {
    case 0: return "P-521";
    case 1: return "P-256";
    case 2: return "P-384";
    case 3: return "P-521";
    default: return NULL;
    }
}

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return alg2crv(alg) != NULL;
}

static bool
jwk_prep_execute(jose_cfg_t *cfg, json_t *jwk)
{
    const char *alg = NULL;
    const char *crv = NULL;
    const char *kty = NULL;
    const char *grp = NULL;

    if (json_unpack(jwk, "{s:s,s?s,s?s}",
                    "alg", &alg, "kty", &kty, "crv", &crv) == -1)
        return false;

    grp = alg2crv(alg);
    if (!grp)
        return false;

    if (kty && strcmp(kty, "EC") != 0)
        return false;

    if (crv && strcmp(crv, grp) != 0)
        return false;

    if (json_object_set_new(jwk, "kty", json_string("EC")) < 0)
        return false;

    if (json_object_set_new(jwk, "crv", json_string(grp)) < 0)
        return false;

    return true;
}

static const char *
alg_wrap_alg(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *name = NULL;
    const char *type = NULL;
    const char *curv = NULL;

    if (json_unpack((json_t *) jwk, "{s?s,s?s,s?s}",
                    "alg", &name, "kty", &type, "crv", &curv) < 0)
        return NULL;

    if (name)
        return str2enum(name, NAMES, NULL) != SIZE_MAX ? name : NULL;

    if (!type || strcmp(type, "EC") != 0)
        return NULL;

    switch (str2enum(curv, "P-256", "P-384", "P-521", NULL)) {
    case 0: return "ECDH-ES+A128KW";
    case 1: return "ECDH-ES+A192KW";
    case 2: return "ECDH-ES+A256KW";
    default: return NULL;
    }
}

static const char *
alg_wrap_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *crv = NULL;

    if (json_unpack((json_t *) jwk, "{s?s}", "crv", &crv) < 0)
        return NULL;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
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
    const jose_hook_alg_t *ecdh = NULL;
    json_auto_t *exc = NULL;
    json_auto_t *hdr = NULL;
    json_auto_t *epk = NULL;
    json_auto_t *der = NULL;
    const char *wrap = NULL;
    json_t *h = NULL;

    if (json_object_get(cek, "k")) {
        if (strcmp(alg->name, "ECDH-ES") == 0)
            return false;
    } else if (!jose_jwk_gen(cfg, cek)) {
        return false;
    }

    hdr = jose_jwe_hdr(jwe, rcp);
    if (!hdr)
        return false;

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1)
        return false;

    epk = json_pack("{s:s,s:O}", "kty", "EC", "crv",
                    json_object_get(jwk, "crv"));
    if (!epk)
        return false;

    if (!jose_jwk_gen(cfg, epk))
        return false;

    ecdh = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_EXCH, "ECDH");
    if (!ecdh)
        return false;

    exc = ecdh->exch.exc(ecdh, cfg, epk, jwk);
    if (!exc)
        return false;

    if (!jose_jwk_pub(cfg, epk))
        return false;

    if (json_object_set(h, "epk", epk) == -1)
        return false;

    der = derive(alg, cfg, hdr, cek, exc);
    if (!der)
        return false;

    wrap = strchr(alg->name, '+');
    if (wrap) {
        const jose_hook_alg_t *kw = NULL;

        kw = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, &wrap[1]);
        if (!kw)
            return false;

        return kw->wrap.wrp(kw, cfg, jwe, rcp, der, cek);
    }

    if (json_object_update(cek, der) < 0)
        return false;

    return add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);
}

static bool
alg_wrap_unw(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *rcp, const json_t *jwk, json_t *cek)
{
    const json_t *epk = NULL;
    json_auto_t *exc = NULL;
    json_auto_t *der = NULL;
    json_auto_t *hdr = NULL;
    const char *wrap = NULL;

    hdr = jose_jwe_hdr(jwe, rcp);
    epk = json_object_get(hdr, "epk");
    if (!hdr || !epk)
        return false;

    /* If the JWK has a private key, perform the normal exchange. */
    if (json_object_get(jwk, "d")) {
        const jose_hook_alg_t *ecdh = NULL;

        ecdh = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_EXCH, "ECDH");
        if (!ecdh)
            return false;

        exc = ecdh->exch.exc(ecdh, cfg, jwk, epk);

    /* Otherwise, allow external exchanges. */
    } else if (json_equal(json_object_get(jwk, "crv"),
                          json_object_get(epk, "crv"))) {
        exc = json_deep_copy(jwk);
    }
    if (!exc)
        return false;

    der = derive(alg, cfg, hdr, cek, exc);
    if (!der)
        return false;

    wrap = strchr(alg->name, '+');
    if (wrap) {
        const jose_hook_alg_t *kw = NULL;

        kw = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, &wrap[1]);
        if (!kw)
            return false;

        return kw->wrap.unw(kw, cfg, jwe, rcp, der, cek);
    }

    return json_object_update(cek, der) == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_PREP,
        .prep.handles = jwk_prep_handles,
        .prep.execute = jwk_prep_execute
    };

    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "ECDH-ES",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "ECDH-ES+A128KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "ECDH-ES+A192KW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "ECDH-ES+A256KW",
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
