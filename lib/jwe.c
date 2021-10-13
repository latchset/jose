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
#include <jose/jwe.h>
#include "hooks.h"

#include <errno.h>
#include <string.h>

#include <unistd.h>

static bool
jwe_hdr_set_new(json_t *jwe, const char *name, json_t *value)
{
    json_auto_t *v = value;
    json_t *p = NULL;
    json_t *u = NULL;

    p = json_object_get(jwe, "protected");
    if (p && !json_is_object(p) && !json_is_string(p))
        return false;

    u = json_object_get(jwe, "unprotected");
    if (u && !json_is_object(u))
        return false;

    if (!u && json_is_string(p) &&
        json_object_set_new(jwe, "unprotected", u = json_object()) < 0)
        return false;

    if (!u && !p &&
        json_object_set_new(jwe, "protected", p = json_object()) < 0)
        return false;

    if (json_object_set(json_is_object(p) ? p : u, name, v) < 0)
        return false;

    return true;
}

json_t *
jose_jwe_hdr(const json_t *jwe, const json_t *rcp)
{
    json_auto_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;

    p = json_incref(json_object_get(jwe, "protected"));
    if (!p) {
        p = json_object();
    } else if (json_is_object(p)) {
        json_decref(p);
        p = json_deep_copy(p);
    } else if (json_is_string(p)) {
        json_decref(p);
        p = jose_b64_dec_load(p);
    }

    if (!json_is_object(p))
        return NULL;

    s = json_object_get(jwe, "unprotected");
    if (s) {
        if (json_object_update_missing(p, s) == -1)
            return NULL;
    }

    h = json_object_get(rcp, "header");
    if (h) {
        if (json_object_update_missing(p, h) == -1)
            return NULL;
    }

    return json_incref(p);
}

bool
jose_jwe_enc(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *jwk,
             const void *pt, size_t ptl)
{
    json_auto_t *cek = NULL;

    cek = json_object();
    if (!cek)
        return NULL;

    if (!jose_jwe_enc_jwk(cfg, jwe, rcp, jwk, cek))
        return NULL;

    return jose_jwe_enc_cek(cfg, jwe, cek, pt, ptl);
}

jose_io_t *
jose_jwe_enc_io(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *jwk,
                jose_io_t *next)
{
    json_auto_t *cek = NULL;

    cek = json_object();
    if (!cek)
        return NULL;

    if (!jose_jwe_enc_jwk(cfg, jwe, rcp, jwk, cek))
        return NULL;

    return jose_jwe_enc_cek_io(cfg, jwe, cek, next);
}

static const jose_hook_alg_t *
find_alg(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *hdr,
         const json_t *jwk)
{
    const jose_hook_alg_t *alg = NULL;
    const char *name = NULL;
    json_t *h = NULL;

    if (json_unpack((json_t *) hdr, "{s:s}", "alg", &name) >= 0)
        return jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, name);

    for (alg = jose_hook_alg_list(); alg && !name; alg = alg->next) {
        if (alg->kind != JOSE_HOOK_ALG_KIND_WRAP)
            continue;
        name = alg->wrap.alg(alg, cfg, jwk);
    }

    if (!name)
        return NULL;

    alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, name);
    if (alg) {
        h = json_object_get(rcp, "header");
        if (!h && json_object_set_new(rcp, "header", h = json_object()) < 0)
            return NULL;

        if (json_object_set_new(h, "alg", json_string(alg->name)) < 0)
            return NULL;
    }

    return alg;
}

static bool
ensure_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
           const json_t *hdr, const json_t *jwk, json_t *cek)
{
    const char *enc = NULL;

    enc = json_string_value(json_object_get(cek, "alg"));
    if (enc)
        return true;

    if (json_unpack((json_t *) hdr, "{s?s}", "enc", &enc) < 0)
        return false;

    /* See if we can infer an enc from the CEK. */
    for (const jose_hook_alg_t *a = jose_hook_alg_list();
         a && !enc; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_ENCR)
            continue;
        enc = a->encr.sug(a, cfg, cek);
    }

    /* See if we can infer an enc from the JWK. */
    if (!enc)
        enc = alg->wrap.enc(alg, cfg, jwk);

    /* Just pick an enc. */
    for (const jose_hook_alg_t *a = jose_hook_alg_list();
         a && !enc; a = a->next) {
        if (a->kind == JOSE_HOOK_ALG_KIND_ENCR)
            enc = a->name;
    }

    return json_object_set_new(cek, "alg", json_string(enc)) >= 0;
}

bool
jose_jwe_enc_jwk(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *jwk,
                 json_t *cek)
{
    const jose_hook_alg_t *alg = NULL;
    json_auto_t *hdr = NULL;
    json_auto_t *r = NULL;

    if (!cek)
        return false;

    if (json_is_array(jwk) || json_is_array(json_object_get(jwk, "keys"))) {
        if (!json_is_array(jwk))
            jwk = json_object_get(jwk, "keys");

        if (json_is_array(rcp) && json_array_size(rcp) != json_array_size(jwk))
            return NULL;

        for (size_t i = 0; i < json_array_size(jwk); i++) {
            json_auto_t *tmp = NULL;

            if (json_is_array(rcp))
                tmp = json_incref(json_array_get(rcp, i));
            else
                tmp = json_deep_copy(rcp);

            if (!jose_jwe_enc_jwk(cfg, jwe, tmp, json_array_get(jwk, i), cek))
                return false;
        }

        return json_array_size(jwk) > 0;
    }

    if (!rcp)
        r = json_object();
    else if (!json_is_object(rcp))
        return false;
    else
        r = json_incref(rcp);

    hdr = jose_jwe_hdr(jwe, r);
    if (!hdr)
        return false;

    alg = find_alg(cfg, jwe, r, hdr, jwk);
    if (!alg)
        return false;

    if (!ensure_enc(alg, cfg, jwe, hdr, jwk, cek))
        return false;

    if (!jose_jwk_prm(cfg, jwk, false, alg->wrap.eprm))
        return false;

    return alg->wrap.wrp(alg, cfg, jwe, r, jwk, cek);
}

bool
jose_jwe_enc_cek(jose_cfg_t *cfg, json_t *jwe, const json_t *cek,
                 const void *pt, size_t ptl)
{
    jose_io_auto_t *i = NULL;
    jose_io_auto_t *o = NULL;
    void *ct = NULL;
    size_t ctl = 0;

    o = jose_io_malloc(cfg, &ct, &ctl);
    i = jose_jwe_enc_cek_io(cfg, jwe, cek, o);
    if (!o || !i || !i->feed(i, pt, ptl) || !i->done(i))
        return false;

    if (json_object_set_new(jwe, "ciphertext", jose_b64_enc(ct, ctl)) < 0)
        return false;

    return true;
}

jose_io_t *
jose_jwe_enc_cek_io(jose_cfg_t *cfg, json_t *jwe, const json_t *cek,
                    jose_io_t *next)
{
    const jose_hook_alg_t *alg = NULL;
    jose_io_auto_t *zip = NULL;
    json_auto_t *prt = NULL;
    const char *h = NULL;
    const char *k = NULL;
    const char *z = NULL;

    prt = jose_b64_dec_load(json_object_get(jwe, "protected"));
    (void) json_unpack(prt, "{s:s}", "zip", &z);

    if (json_unpack(jwe, "{s?{s?s}}", "unprotected", "enc", &h) < 0)
        return NULL;

    if (json_unpack(jwe, "{s?{s?s}}", "protected", "enc", &h) < 0)
        return NULL;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &k) < 0)
        return NULL;

    if (!h) {
        h = k;

        for (alg = jose_hook_alg_list(); alg && !h; alg = alg->next) {
            if (alg->kind != JOSE_HOOK_ALG_KIND_ENCR)
                continue;
            h = alg->encr.sug(alg, cfg, cek);
        }

        if (!h) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOINFER,
                         "Unable to infer encryption algorithm");
            return NULL;
        }

        alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_ENCR, h);
        if (alg && !jwe_hdr_set_new(jwe, "enc", json_string(alg->name)))
            return NULL;
    } else {
        if (k && strcmp(h, k) != 0) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_MISMATCH,
                         "Algorithm mismatch (%s != %s)", h, k);
            return NULL;
        }

        alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_ENCR, h);
    }

    if (!alg) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOTSUP,
                     "Unsupported encryption algorithm (%s)", h);
        return NULL;
    }

    if (!jose_jwk_prm(cfg, cek, false, alg->encr.eprm)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_DENIED,
                     "CEK is not allowed to encrypt");
        return NULL;
    }

    if (!encode_protected(jwe))
        return NULL;

    if (z) {
        const jose_hook_alg_t *a = NULL;

        a = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_COMP, z);
        if (!a)
            return NULL;

        zip = a->comp.def(a, cfg, next);
        if (!zip)
            return NULL;
    }

    return alg->encr.enc(alg, cfg, jwe, cek, zip ? zip : next);
}

void *
jose_jwe_dec(jose_cfg_t *cfg, const json_t *jwe, const json_t *rcp,
             const json_t *jwk, size_t *ptl)
{
    json_auto_t *cek = NULL;

    cek = jose_jwe_dec_jwk(cfg, jwe, rcp, jwk);
    if (!cek)
        return NULL;

    return jose_jwe_dec_cek(cfg, jwe, cek, ptl);
}

jose_io_t *
jose_jwe_dec_io(jose_cfg_t *cfg, const json_t *jwe, const json_t *rcp,
                const json_t *jwk, jose_io_t *next)
{
    json_auto_t *cek = NULL;

    cek = jose_jwe_dec_jwk(cfg, jwe, rcp, jwk);
    if (!cek)
        return NULL;

    return jose_jwe_dec_cek_io(cfg, jwe, cek, next);
}

json_t *
jose_jwe_dec_jwk(jose_cfg_t *cfg, const json_t *jwe, const json_t *rcp,
                 const json_t *jwk)
{
    const jose_hook_alg_t *alg = NULL;
    const char *halg = NULL;
    const char *henc = NULL;
    const char *kalg = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *hdr = NULL;

    if (json_is_array(jwk) || json_is_array(json_object_get(jwk, "keys"))) {
        if (!json_is_array(jwk))
            jwk = json_object_get(jwk, "keys");

        for (size_t i = 0; i < json_array_size(jwk) && !cek; i++)
            cek = jose_jwe_dec_jwk(cfg, jwe, rcp, json_array_get(jwk, i));

        return json_incref(cek);
    }

    if (!rcp) {
        const json_t *rcps = NULL;

        rcps = json_object_get(jwe, "recipients");
        if (json_is_array(rcps)) {
            for (size_t i = 0; i < json_array_size(rcps) && !cek; i++)
                cek = jose_jwe_dec_jwk(cfg, jwe, json_array_get(rcps, i), jwk);
        } else if (!rcps) {
            cek = jose_jwe_dec_jwk(cfg, jwe, jwe, jwk);
        }

        return json_incref(cek);
    }

    hdr = jose_jwe_hdr(jwe, rcp);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s?s,s?s}", "alg", &halg, "enc", &henc) == -1)
        return NULL;

    kalg = json_string_value(json_object_get(jwk, "alg"));
    if (!halg)
        halg = kalg;
    else if (kalg && strcmp(halg, kalg) != 0 &&
             (!henc || strcmp(henc, kalg) != 0))
        return NULL;

    alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_WRAP, halg);
    if (!alg)
        return NULL;

    if (!jose_jwk_prm(cfg, jwk, false, alg->wrap.dprm))
        return NULL;

    cek = json_pack("{s:s,s:s,s:O,s:[ss]}",
                    "kty", "oct", "use", "enc",
                    "enc", json_object_get(hdr, "enc"),
                    "key_ops", "encrypt", "decrypt");
    if (!cek)
        return NULL;

    if (!alg->wrap.unw(alg, cfg, jwe, rcp, jwk, cek))
        return NULL;

    return json_incref(cek);
}

void *
jose_jwe_dec_cek(jose_cfg_t *cfg, const json_t *jwe, const json_t *cek,
                 size_t *ptl)
{
    jose_io_auto_t *d = NULL;
    jose_io_auto_t *i = NULL;
    jose_io_auto_t *o = NULL;
    const char *ct = NULL;
    void *pt = NULL;
    size_t ctl = 0;

    if (json_unpack((json_t *) jwe, "{s:s%}", "ciphertext", &ct, &ctl) < 0)
        return NULL;

    o = jose_io_malloc(cfg, &pt, ptl);
    d = jose_jwe_dec_cek_io(cfg, jwe, cek, o);
    i = jose_b64_dec_io(d);
    if (!o || !d || !i || !i->feed(i, ct, ctl) || !i->done(i))
        return NULL;

    return jose_io_malloc_steal(&pt);
}

jose_io_t *
jose_jwe_dec_cek_io(jose_cfg_t *cfg, const json_t *jwe, const json_t *cek,
                    jose_io_t *next)
{
    const jose_hook_alg_t *alg = NULL;
    jose_io_auto_t *zip = NULL;
    json_auto_t *hdr = NULL;
    json_auto_t *prt = NULL;
    const char *kalg = NULL;
    const char *halg = NULL;
    const char *hzip = NULL;

    prt = jose_b64_dec_load(json_object_get(jwe, "protected"));
    (void) json_unpack(prt, "{s:s}", "zip", &hzip);

    hdr = jose_jwe_hdr(jwe, NULL);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s?s}", "enc", &halg) < 0)
        return NULL;

    if (json_unpack((json_t *) cek, "{s?s}", "alg", &kalg) < 0)
        return NULL;

    if (!halg && !kalg) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOINFER,
                     "Decryption algorithm cannot be inferred");
        return NULL;
    } else if (halg && kalg && strcmp(halg, kalg) != 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_MISMATCH,
                     "Algorithm mismatch (%s != %s)", halg, kalg);
        return NULL;
    }

    alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_ENCR, halg ? halg : kalg);
    if (!alg)
        return NULL;

    if (!jose_jwk_prm(cfg, cek, false, alg->encr.dprm))
        return NULL;

    if (hzip) {
        const jose_hook_alg_t *a = NULL;

        a = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_COMP, hzip);
        if (!a)
            return NULL;

        zip = a->comp.inf(a, cfg, next);
        if (!zip)
            return NULL;
    }

    return alg->encr.dec(alg, cfg, jwe, cek, zip ? zip : next);
}
