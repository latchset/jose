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
#include <jose/jws.h>
#include "hooks.h"

#include <errno.h>
#include <string.h>

static const jose_hook_alg_t *
find_alg(jose_cfg_t *cfg, json_t *jws, json_t *sig, const json_t *jwk)
{
    const jose_hook_alg_t *alg = NULL;
    const char *halg = NULL;
    const char *kalg = NULL;
    json_auto_t *hdr = NULL;

    hdr = jose_jws_hdr(sig);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s:s}", "alg", &halg) < 0) {
        for (alg = jose_hook_alg_list(); alg && !halg; alg = alg->next) {
            if (alg->kind != JOSE_HOOK_ALG_KIND_SIGN)
                continue;
            halg = alg->sign.sug(alg, cfg, jwk);
        }

        if (!halg) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOINFER,
                         "Unable to infer signing algorithm");
            return NULL;
        }

        alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_SIGN, halg);
        if (alg) {
            json_t *h = NULL;

            h = json_object_get(sig, "protected");
            if (!h && json_object_set_new(sig, "protected", h = json_object()) < 0)
                return NULL;

            if (json_object_set_new(h, "alg", json_string(alg->name)) < 0)
                return NULL;
        }
    } else {
        alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_SIGN, halg);
    }

    if (!alg) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOTSUP,
                     "Signing algorithm (%s) is not supported", halg);
        return NULL;
    }

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) < 0)
        return NULL;

    if (halg && kalg && strcmp(halg, kalg) != 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_MISMATCH,
                     "Algorithm mismatch (%s != %s)", halg, kalg);
        return NULL;
    }

    if (!jose_jwk_prm(cfg, jwk, false, alg->sign.sprm)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_DENIED,
                     "JWK cannot be used to sign");
        return NULL;
    }

    return alg;
}

static void
ios_auto(jose_io_t ***iosp)
{
    jose_io_t **ios = *iosp;

    for (size_t i = 0; ios && ios[i]; i++)
        jose_io_auto(&ios[i]);

    free(ios);
}

json_t *
jose_jws_hdr(const json_t *sig)
{
    json_auto_t *p = NULL;
    json_t *h = NULL;

    p = json_object_get(sig, "protected");
    if (!p)
        p = json_object();
    else if (json_is_object(p))
        p = json_deep_copy(p);
    else if (json_is_string(p))
        p = jose_b64_dec_load(p);

    if (!json_is_object(p))
        return NULL;

    h = json_object_get(sig, "header");
    if (h) {
        if (json_object_update_missing(p, h) == -1)
            return NULL;
    }

    return json_incref(p);
}

bool
jose_jws_sig(jose_cfg_t *cfg, json_t *jws, json_t *sig, const json_t *jwk)
{
    jose_io_auto_t *io = NULL;
    const char *pay = NULL;
    size_t payl = 0;

    if (json_unpack(jws, "{s:s%}", "payload", &pay, &payl) < 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWS_INVALID,
                     "JWS missing payload attribute");
        return false;
    }

    io = jose_jws_sig_io(cfg, jws, sig, jwk);
    return io && io->feed(io, pay, payl) && io->done(io);
}

jose_io_t *
jose_jws_sig_io(jose_cfg_t *cfg, json_t *jws, json_t *sig, const json_t *jwk)
{
    const jose_hook_alg_t *alg = NULL;
    json_auto_t *s = NULL;

    if (json_is_array(jwk) || json_is_array(json_object_get(jwk, "keys"))) {
        jose_io_t __attribute__((cleanup(ios_auto))) **ios = NULL;
        const json_t *key = NULL;
        size_t i = 0;

        if (!json_is_array(jwk))
            jwk = json_object_get(jwk, "keys");

        if (json_is_array(sig) && json_array_size(sig) != json_array_size(jwk))
            return NULL;

        ios = calloc(json_array_size(jwk) + 1, sizeof(*ios));
        if (!ios)
            return NULL;

        json_array_foreach(jwk, i, key) {
            json_auto_t *tmp = NULL;

            if (json_is_array(sig))
                tmp = json_incref(json_array_get(sig, i));
            else
                tmp = json_deep_copy(sig);

            ios[i] = jose_jws_sig_io(cfg, jws, tmp, key);
            if (!ios[i])
                return NULL;
        }

        return jose_io_multiplex(cfg, ios, true);
    }

    s = sig ? json_incref(sig) : json_object();
    if (!json_is_object(s)) {
        jose_cfg_err(cfg, EINVAL, "Parameter sig MUST be an object or NULL");
        return NULL;
    }

    alg = find_alg(cfg, jws, s, jwk);
    if (!alg)
        return NULL;

    if (!encode_protected(s))
        return NULL;

    return alg->sign.sig(alg, cfg, jws, s, jwk);
}

bool
jose_jws_ver(jose_cfg_t *cfg, const json_t *jws, const json_t *sig,
             const json_t *jwk, bool all)
{
    jose_io_auto_t *io = NULL;
    const char *pay = NULL;
    size_t payl = 0;

    if (json_unpack((json_t *) jws, "{s:s%}", "payload", &pay, &payl) < 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWS_INVALID,
                     "JWS missing payload attribute");
        return false;
    }

    io = jose_jws_ver_io(cfg, jws, sig, jwk, all);
    return io && io->feed(io, pay, payl) && io->done(io);
}

jose_io_t *
jose_jws_ver_io(jose_cfg_t *cfg, const json_t *jws, const json_t *sig,
                const json_t *jwk, bool all)
{
    const jose_hook_alg_t *alg = NULL;
    const char *kalg = NULL;
    const char *halg = NULL;
    json_auto_t *hdr = NULL;

    if (json_is_array(jwk) || json_is_array(json_object_get(jwk, "keys"))) {
        jose_io_t __attribute__((cleanup(ios_auto))) **ios = NULL;
        size_t j = 0;

        if (!json_is_array(jwk))
            jwk = json_object_get(jwk, "keys");

        if (json_is_array(sig) && json_array_size(sig) != json_array_size(jwk))
            return NULL;

        ios = calloc(json_array_size(jwk) + 1, sizeof(*ios));
        if (!ios)
            return NULL;

        for (size_t i = 0; i < json_array_size(jwk); i++) {
            const json_t *s = json_is_object(sig) ? sig : json_array_get(sig, i);
            const json_t *k = json_array_get(jwk, i);
            ios[j] = jose_jws_ver_io(cfg, jws, s, k, false);
            if (ios[j])
                j++;
            else if (all)
                return NULL;
        }

        return jose_io_multiplex(cfg, ios, all);
    }

    if (!sig) {
        jose_io_t __attribute__((cleanup(ios_auto))) **ios = NULL;
        const json_t *array = NULL;
        const json_t *s = NULL;
        size_t i = 0;
        size_t j = 0;

        array = json_object_get(jws, "signatures");
        if (!json_is_array(array))
            return jose_jws_ver_io(cfg, jws, jws, jwk, true);

        ios = calloc(json_array_size(array) + 1, sizeof(*ios));
        if (!ios)
            return NULL;

        json_array_foreach(array, i, s) {
            ios[j] = jose_jws_ver_io(cfg, jws, s, jwk, true);
            if (ios[j])
                j++;
        }

        return jose_io_multiplex(cfg, ios, false);
    } else if (!json_is_object(sig))
        return NULL;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) < 0)
        return NULL;

    hdr = jose_jws_hdr(sig);
    if (!hdr)
        return NULL;

    if (json_unpack(hdr, "{s?s}", "alg", &halg) < 0)
        return NULL;

    if (!halg) {
        if (!kalg) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOINFER,
                         "Signature algorithm cannot be inferred");
            return NULL;
        }

        halg = kalg;
    } else if (kalg && strcmp(halg, kalg) < 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_MISMATCH,
                     "Signing algorithm mismatch (%s != %s)", halg, kalg);
        return NULL;
    }

    alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_SIGN, halg);
    if (!alg) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOTSUP,
                     "Signing algorithm (%s) is not supported", halg);
        return NULL;
    }

    if (!jose_jwk_prm(cfg, jwk, false, alg->sign.vprm)) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_DENIED,
                     "JWK cannot be used to verify");
        return false;
    }

    return alg->sign.ver(alg, cfg, jws, sig, jwk);
}
