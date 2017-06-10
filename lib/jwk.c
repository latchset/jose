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

#include <jose/b64.h>
#include <jose/jwk.h>
#include "hooks.h"
#include "misc.h"
#include "hsh.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static bool
jwk_hook(jose_cfg_t *cfg, json_t *jwk, jose_hook_jwk_kind_t kind, bool dflt)
{
    for (const jose_hook_jwk_t *j = jose_hook_jwk_list(); j; j = j->next) {
        json_auto_t *upd = NULL;
        const char *key = NULL;
        json_t *val = NULL;
        size_t i = 0;

        if (j->kind != kind)
            continue;

        if (!j->prep.handles(cfg, jwk))
            continue;

        upd = j->prep.execute(cfg, jwk);
        if (!json_is_object(upd))
            return false;

        json_array_foreach(json_object_get(upd, "del"), i, val) {
            if (!json_object_get(jwk, json_string_value(val)))
                continue;
            if (json_object_del(jwk, json_string_value(val)) < 0)
                return false;
        }

        json_object_foreach(json_object_get(upd, "upd"), key, val) {
            json_t *src = json_object_get(jwk, key);

            if (src && !json_equal(src, val))
                return false;

            if (json_object_set(jwk, key, val) < 0)
                return false;
        }

        return true;
    }

    return dflt;
}

bool
jose_jwk_gen(jose_cfg_t *cfg, json_t *jwk)
{
    const json_t *ko = NULL;
    const char *alg = NULL;
    const char *kty = NULL;
    const char *use = NULL;

    if (!jwk_hook(cfg, jwk, JOSE_HOOK_JWK_KIND_PREP, true))
        return false;

    if (!jwk_hook(cfg, jwk, JOSE_HOOK_JWK_KIND_MAKE, false))
        return false;

    if (json_unpack(jwk, "{s?s,s:s,s?s,s?o}",
                    "alg", &alg, "kty", &kty, "use", &use, "key_ops", &ko) < 0)
        return false;

    for (const jose_hook_alg_t *a = jose_hook_alg_list();
         a && alg && !use && !ko; a = a->next) {
        json_auto_t *ops = NULL;

        if (strcmp(alg, a->name) != 0)
            continue;

        ops = json_array();
        if (!ops)
            return false;

        switch (a->kind) {
        case JOSE_HOOK_ALG_KIND_SIGN:
            if (json_array_append_new(ops, json_string("sign")) < 0)
                return false;
            if (json_array_append_new(ops, json_string("verify")) < 0)
                return false;
            break;
        case JOSE_HOOK_ALG_KIND_WRAP:
            if (json_array_append_new(ops, json_string("wrapKey")) < 0)
                return false;
            if (json_array_append_new(ops, json_string("unwrapKey")) < 0)
                return false;
            break;
        case JOSE_HOOK_ALG_KIND_ENCR:
            if (json_array_append_new(ops, json_string("encrypt")) < 0)
                return false;
            if (json_array_append_new(ops, json_string("decrypt")) < 0)
                return false;
            break;
        case JOSE_HOOK_ALG_KIND_EXCH:
            if (json_array_append_new(ops, json_string("deriveKey")) < 0)
                return false;
            break;
        default:
            break;
        }

        if (json_array_size(ops) > 0 &&
            json_object_set(jwk, "key_ops", ops) < 0)
            return false;

        break;
    }

    for (const jose_hook_jwk_t *j = jose_hook_jwk_list(); j; j = j->next) {
        if (j->kind != JOSE_HOOK_JWK_KIND_TYPE)
            continue;

        if (strcmp(j->type.kty, kty) == 0) {
            for (size_t i = 0; j->type.req[i]; i++) {
                if (!json_object_get(jwk, j->type.req[i]))
                    return false;
            }

            return true;
        }
    }

    return false;
}

static bool
jwk_clean(jose_cfg_t *cfg, json_t *jwk)
{
    const jose_hook_jwk_t *type = NULL;
    const char *kty = NULL;
    bool sym = false;

    if (json_unpack(jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    for (type = jose_hook_jwk_list(); type; type = type->next) {
        if (type->kind != JOSE_HOOK_JWK_KIND_TYPE)
            continue;

        if (strcasecmp(kty, type->type.kty) == 0)
            break;
    }

    if (!type)
        return false;

    sym = !type->type.pub || !type->type.pub[0];

    for (size_t i = 0; type->type.prv[i]; i++) {
        if (!json_object_get(jwk, type->type.prv[i]))
            continue;

        if (json_object_del(jwk, type->type.prv[i]) == -1)
            return false;
    }

    for (const jose_hook_jwk_t *o = jose_hook_jwk_list(); o; o = o->next) {
        json_t *arr = NULL;

        if (o->kind != JOSE_HOOK_JWK_KIND_OPER)
            continue;

        if (!o->oper.prv && (!sym || !o->oper.pub))
            continue;

        arr = json_object_get(jwk, "key_ops");
        for (size_t i = 0; i < json_array_size(arr); i++) {
            const char *ko = NULL;

            ko = json_string_value(json_array_get(arr, i));
            if (!ko)
                continue;

            if ((!o->oper.prv || strcmp(o->oper.prv, ko) != 0) &&
                (!sym || !o->oper.pub || strcmp(o->oper.pub, ko) != 0))
                continue;

            if (json_array_remove(arr, i--) == -1)
                return false;
        }
    }

    return true;
}

bool
jose_jwk_pub(jose_cfg_t *cfg, json_t *jwk)
{
    json_t *keys = NULL;

    if (json_is_array(jwk))
        keys = jwk;
    else if (json_is_array(json_object_get(jwk, "keys")))
        keys = json_object_get(jwk, "keys");

    if (!keys)
        return jwk_clean(cfg, jwk);

    for (size_t i = 0; i < json_array_size(keys); i++) {
        if (!jwk_clean(cfg, json_array_get(keys, i)))
            return false;
    }

    return true;
}

bool
jose_jwk_prm(jose_cfg_t *cfg, const json_t *jwk, bool req, const char *op)
{
    const char *use = NULL;
    json_t *ko = NULL;

    if (!json_is_object(jwk))
        return true;

    if (!op)
        return false;

    if (json_unpack((json_t *) jwk, "{s?s,s?o}",
                    "use", &use, "key_ops", &ko) != 0)
        return false;

    if (!use && !ko)
        return !req;

    for (size_t i = 0; i < json_array_size(ko); i++) {
        json_t *v = json_array_get(ko, i);

        if (json_is_string(v) && strcmp(op, json_string_value(v)) == 0)
            return true;
    }

    for (const jose_hook_jwk_t *o = jose_hook_jwk_list(); use && o; o = o->next) {
        if (o->kind != JOSE_HOOK_JWK_KIND_OPER)
            continue;

        if (!o->oper.use || strcmp(use, o->oper.use) != 0)
            continue;

        if (o->oper.pub && strcmp(op, o->oper.pub) == 0)
            return true;

        if (o->oper.prv && strcmp(op, o->oper.prv) == 0)
            return true;
    }

    return false;
}

static const jose_hook_jwk_t *
find_type(const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) < 0)
        return NULL;

    for (const jose_hook_jwk_t *t = jose_hook_jwk_list(); t; t = t->next) {
        if (t->kind != JOSE_HOOK_JWK_KIND_TYPE)
            continue;
        if (strcasecmp(kty, t->type.kty) == 0)
            return t;
    }

    return NULL;
}

bool
jose_jwk_eql(jose_cfg_t *cfg, const json_t *a, const json_t *b)
{
    const jose_hook_jwk_t *type = NULL;

    type = find_type(a);
    if (!type)
        return false;

    if (!json_equal(json_object_get(a, "kty"), json_object_get(b, "kty")))
        return false;

    for (size_t i = 0; type->type.req[i]; i++) {
        json_t *aa = json_object_get(a, type->type.req[i]);
        json_t *bb = json_object_get(b, type->type.req[i]);

        if (!aa || !bb || !json_equal(aa, bb))
            return false;
    }

    return true;
}

static char *
jwk_str(const json_t *jwk)
{
    const jose_hook_jwk_t *type = NULL;
    json_auto_t *key = NULL;

    type = find_type(jwk);
    if (!type)
        return NULL;

    key = json_object();
    if (!key)
        return NULL;

    if (json_object_set(key, "kty", json_object_get(jwk, "kty")) < 0)
        return NULL;

    for (size_t i = 0; type->type.req[i]; i++) {
        json_t *tmp = NULL;

        tmp = json_object_get(jwk, type->type.req[i]);
        if (!tmp)
            return NULL;

        if (json_object_set(key, type->type.req[i], tmp) < 0)
            return NULL;
    }

    return json_dumps(key, JSON_SORT_KEYS | JSON_COMPACT);
}

json_t *
jose_jwk_thp(jose_cfg_t *cfg, const json_t *jwk, const char *hash)
{
    json_t *thp = NULL;
    char *str = NULL;

    str = jwk_str(jwk);
    if (!str)
        return NULL;

    thp = hsh(cfg, hash, str, strlen(str));
    zero(str, strlen(str));
    free(str);
    return thp;
}

size_t
jose_jwk_thp_buf(jose_cfg_t *cfg, const json_t *jwk,
                 const char *alg, uint8_t *thp, size_t len)
{
    char *str = NULL;

    if (!thp || len == 0)
        return hsh_buf(cfg, alg, NULL, 0, NULL, 0);

    str = jwk_str(jwk);
    if (!str)
        return SIZE_MAX;

    len = hsh_buf(cfg, alg, str, strlen(str), thp, len);
    zero(str, strlen(str));
    free(str);
    return len;
}

json_t *
jose_jwk_exc(jose_cfg_t *cfg, const json_t *prv, const json_t *pub)
{
    const char *alga = NULL;
    const char *algb = NULL;
    const char *ktya = NULL;
    const char *ktyb = NULL;

    if (json_unpack((json_t *) prv, "{s:s,s?s}",
                    "kty", &ktya, "alg", &alga) < 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID, "Private JWK is invalid");
        return NULL;
    }

    if (json_unpack((json_t *) pub, "{s:s,s?s}",
                    "kty", &ktyb, "alg", &algb) < 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_INVALID, "Public JWK is invalid");
        return NULL;
    }

    if (strcmp(ktya, ktyb) != 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_MISMATCH,
                     "Public and private JWKs are different types");
        return NULL;
    }

    if (alga && algb && strcmp(alga, algb) != 0) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_MISMATCH,
                     "Public and private JWKs have different algorithms");
        return NULL;
    }

    for (const jose_hook_alg_t *a = jose_hook_alg_list();
         !alga && !algb && a; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_EXCH)
            continue;

        alga = a->exch.sug(a, cfg, prv, pub);
    }

    if (!alga && !algb) {
        jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOINFER,
                     "Exchange algorithm cannot be inferred");
        return NULL;
    }

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_EXCH)
            continue;

        if (strcmp(alga ? alga : algb, a->name) != 0)
            continue;

        if (!jose_jwk_prm(cfg, prv, false, a->exch.prm)) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_DENIED,
                         "Private JWK cannot be used to derive keys");
            return NULL;
        }

        if (!jose_jwk_prm(cfg, pub, false, a->exch.prm)) {
            jose_cfg_err(cfg, JOSE_CFG_ERR_JWK_DENIED,
                         "Public JWK cannot be used to derive keys");
            return NULL;
        }

        return a->exch.exc(a, cfg, prv, pub);
    }

    jose_cfg_err(cfg, JOSE_CFG_ERR_ALG_NOTSUP,
                 "Exchange algorithm %s is unsupported", alga ? alga : algb);
    return NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *oct_req[] = { "k", NULL };
    static const char *oct_prv[] = { "k", NULL };

    static const char *rsa_req[] = { "e", "n", NULL };
    static const char *rsa_pub[] = { "e", "n", NULL };
    static const char *rsa_prv[] = { "p", "d", "q", "dp", "dq", "qi", "oth", NULL };

    static const char *ec_req[] = { "crv", "x", "y", NULL };
    static const char *ec_pub[] = { "x", "y", NULL };
    static const char *ec_prv[] = { "d", NULL };

    static jose_hook_jwk_t hooks[] = {
        { .kind = JOSE_HOOK_JWK_KIND_TYPE,
          .type = { .kty = "oct", .req = oct_req, .prv = oct_prv } },
        { .kind = JOSE_HOOK_JWK_KIND_TYPE,
          .type = { .kty = "RSA", .req = rsa_req, .pub = rsa_pub, .prv = rsa_prv } },
        { .kind = JOSE_HOOK_JWK_KIND_TYPE,
          .type = { .kty = "EC", .req = ec_req, .pub = ec_pub, .prv = ec_prv } },
        { .kind = JOSE_HOOK_JWK_KIND_OPER,
          .oper = { .pub = "verify", .prv = "sign", .use = "sig" } },
        { .kind = JOSE_HOOK_JWK_KIND_OPER,
          .oper = { .pub = "encrypt", .prv = "decrypt", .use = "enc" } },
        { .kind = JOSE_HOOK_JWK_KIND_OPER,
          .oper = { .pub = "wrapKey", .prv = "unwrapKey", .use = "enc" } },
        { .kind = JOSE_HOOK_JWK_KIND_OPER,
          .oper = { .pub = "deriveKey" } },
        { .kind = JOSE_HOOK_JWK_KIND_OPER,
          .oper = { .pub = "deriveBits" } },
        {}
    };

    for (size_t i = 0; hooks[i].kind != JOSE_HOOK_JWK_KIND_NONE; i++)
        jose_hook_jwk_push(&hooks[i]);
}
