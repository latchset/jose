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

declare_cleanup(EC_KEY)

static bool
jwk_make_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    return strcmp(kty, "EC") == 0;
}

static json_t *
jwk_make_execute(jose_cfg_t *cfg, const json_t *jwk)
{
    openssl_auto(EC_KEY) *key = NULL;
    const char *crv = "P-256";
    int nid = NID_undef;

    if (!jwk_make_handles(cfg, jwk))
        return false;

    if (json_unpack((json_t *) jwk, "{s?s}", "crv", &crv) == -1)
        return false;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: nid = NID_X9_62_prime256v1; break;
    case 1: nid = NID_secp384r1; break;
    case 2: nid = NID_secp521r1; break;
    default: return false;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return false;

    if (EC_KEY_generate_key(key) <= 0)
        return false;

    return json_pack("{s:o}", "upd", jose_openssl_jwk_from_EC_KEY(cfg, key));
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_jwk_t jwk = {
        .kind = JOSE_HOOK_JWK_KIND_MAKE,
        .make.handles = jwk_make_handles,
        .make.execute = jwk_make_execute
    };

    jose_hook_jwk_push(&jwk);
}
