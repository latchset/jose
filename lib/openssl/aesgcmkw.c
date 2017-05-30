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
#include <string.h>

#define NAMES "A128GCMKW", "A192GCMKW", "A256GCMKW"

static inline const char *
kw2enc(const jose_hook_alg_t *alg)
{
    switch (str2enum(alg->name, NAMES, NULL)) {
    case 0: return "A128GCM";
    case 1: return "A192GCM";
    case 2: return "A256GCM";
    default: return NULL;
    }
}

static inline const jose_hook_alg_t *
kw2alg(const jose_hook_alg_t *alg)
{
    const char *enc = NULL;

    enc = kw2enc(alg);
    if (!enc)
        return NULL;

    return jose_hook_alg_find(JOSE_HOOK_ALG_KIND_ENCR, enc);
}

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

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
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
    case 16: return "A128GCMKW";
    case 24: return "A192GCMKW";
    case 32: return "A256GCMKW";
    default: break;
    }

    return NULL;
}

static const char *
alg_wrap_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    return kw2enc(alg);
}

static bool
alg_wrap_wrp(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
             json_t *rcp, const json_t *jwk, json_t *cek)
{
    const jose_hook_alg_t *enc = NULL;
    jose_io_auto_t *e = NULL;
    jose_io_auto_t *d = NULL;
    jose_io_auto_t *c = NULL;
    jose_io_auto_t *p = NULL;
    json_auto_t *tmp = NULL;
    const char *k = NULL;
    json_t *h = NULL;
    void *ct = NULL;
    void *pt = NULL;
    size_t ptl = 0;
    size_t ctl = 0;
    size_t kl = 0;

    if (!json_object_get(cek, "k") && !jose_jwk_gen(cfg, cek))
        return false;

    /* Obtain the plaintext to wrap. */
    if (json_unpack(cek, "{s:s%}", "k", &k, &kl) < 0)
        return false;

    p = jose_io_malloc(cfg, &pt, &ptl);
    if (!p)
        return false;

    d = jose_b64_dec_io(p);
    if (!d || !d->feed(d, k, kl) || !d->done(d))
        return false;

    /* Perform the wrapping. */
    enc = kw2alg(alg);
    if (!enc)
        return false;

    tmp = json_object();
    if (!tmp)
        return false;

    c = jose_io_malloc(cfg, &ct, &ctl);
    if (!c)
        return false;

    e = enc->encr.enc(enc, cfg, tmp, jwk, c);
    if (!e || !e->feed(e, pt, ptl) || !e->done(e))
        return false;

    /* Save the output. */
    h = json_object_get(rcp, "header");
    if (!h) {
        if (json_object_set_new(rcp, "header", h = json_object()) < 0)
            return false;
    }
    if (!json_is_object(h))
        return false;

    if (json_object_update(h, tmp) < 0)
        return false;

    if (json_object_set_new(rcp, "encrypted_key", jose_b64_enc(ct, ctl)) < 0)
        return false;

    return add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);
}

static bool
alg_wrap_unw(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *rcp, const json_t *jwk, json_t *cek)
{
    const jose_hook_alg_t *enc = NULL;
    jose_io_auto_t *c = NULL;
    jose_io_auto_t *d = NULL;
    jose_io_auto_t *p = NULL;
    json_auto_t *hdr = NULL;
    json_auto_t *tmp = NULL;
    const char *ct = NULL;
    void *pt = NULL;
    size_t ptl = 0;
    size_t ctl = 0;

    /* Prepare synthetic JWE */
    hdr = jose_jwe_hdr(jwe, rcp);
    if (!hdr)
        return false;

    tmp = json_object();
    if (!tmp)
        return false;

    if (json_object_set(tmp, "iv", json_object_get(hdr, "iv")) < 0)
        return false;

    if (json_object_set(tmp, "tag", json_object_get(hdr, "tag")) < 0)
        return false;

    /* Perform the unwrap. */
    if (json_unpack((json_t *) rcp, "{s:s%}", "encrypted_key", &ct, &ctl) < 0)
        return false;

    enc = kw2alg(alg);
    if (!enc)
        return false;

    p = jose_io_malloc(cfg, &pt, &ptl);
    if (!p)
        return false;

    c = enc->encr.dec(enc, cfg, tmp, jwk, p);
    if (!c)
        return false;

    d = jose_b64_dec_io(c);
    if (!d || !d->feed(d, ct, ctl) || !d->done(d))
        return false;

    /* Set the output value */
    if (json_object_set_new(cek, "k", jose_b64_enc(pt, ptl)) < 0)
        return false;

    return true;
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
          .name = "A128GCMKW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "A192GCMKW",
          .wrap.eprm = "wrapKey",
          .wrap.dprm = "unwrapKey",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "A256GCMKW",
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
