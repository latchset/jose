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
#include "../hooks.h"
#include <jose/openssl.h>

#include <string.h>

declare_cleanup(EC_POINT)
declare_cleanup(EC_KEY)
declare_cleanup(BN_CTX)

static bool
jwk_prep_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &alg) == -1)
        return false;

    return strcmp(alg, "ECMR") == 0;
}

static json_t *
jwk_prep_execute(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *crv = "P-521";
    const char *alg = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s?s}", "alg", &alg, "crv", &crv) < 0)
        return false;

    if (strcmp(alg, "ECMR") != 0)
        return false;

    return json_pack("{s:{s:s,s:s}}", "upd", "kty", "EC", "crv", crv);
}

static const char *
alg_exch_sug(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
             const json_t *prv, const json_t *pub)
{
    return NULL;
}

static json_t *
alg_exch_exc(const jose_hook_alg_t *alg, jose_cfg_t *cfg,
             const json_t *prv, const json_t *pub)
{
    openssl_auto(EC_KEY) *lcl = NULL;
    openssl_auto(EC_KEY) *rem = NULL;
    openssl_auto(BN_CTX) *bnc = NULL;
    openssl_auto(EC_POINT) *p = NULL;
    const EC_GROUP *grp = NULL;

    bnc = BN_CTX_new();
    if (!bnc)
        return NULL;

    lcl = jose_openssl_jwk_to_EC_KEY(cfg, prv);
    if (!lcl)
        return NULL;

    rem = jose_openssl_jwk_to_EC_KEY(cfg, pub);
    if (!rem)
        return NULL;

    grp = EC_KEY_get0_group(lcl);
    if (EC_GROUP_cmp(grp, EC_KEY_get0_group(rem), bnc) != 0)
        return NULL;

    p = EC_POINT_new(grp);
    if (!p)
        return NULL;

    if (EC_KEY_get0_private_key(lcl)) {
        if (EC_POINT_mul(grp, p, NULL, EC_KEY_get0_public_key(rem),
                         EC_KEY_get0_private_key(lcl), bnc) <= 0)
            return NULL;
    } else {
        if (EC_POINT_copy(p, EC_KEY_get0_public_key(rem)) < 0)
            return NULL;

        if (!EC_KEY_get0_private_key(rem)) {
            if (EC_POINT_invert(grp, p, bnc) < 0)
                return NULL;
        }

        if (EC_POINT_add(grp, p, EC_KEY_get0_public_key(lcl), p, bnc) <= 0)
            return NULL;
    }

    return jose_openssl_jwk_from_EC_POINT(cfg, EC_KEY_get0_group(rem), p, NULL);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_PREP,
        .prep.handles = jwk_prep_handles,
        .prep.execute = jwk_prep_execute
    };

    static jose_hook_alg_t ecdh[] = {
        { .name = "ECMR",
          .kind = JOSE_HOOK_ALG_KIND_EXCH,
          .exch.prm = "deriveKey",
          .exch.sug = alg_exch_sug,
          .exch.exc = alg_exch_exc },
        {}
    };

    jose_hook_jwk_push(&jwk);
    for (size_t i = 0; ecdh[i].name; i++)
        jose_hook_alg_push(&ecdh[i]);
}
