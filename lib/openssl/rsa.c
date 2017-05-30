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

static RSA *
mkrsa(const json_t *jwk)
{
    openssl_auto(BIGNUM) *bn = NULL;
    json_auto_t *exp = NULL;
    RSA *key = NULL;
    int bits = 2048;

    if (json_unpack((json_t *) jwk, "{s?i,s?O}",
                    "bits", &bits, "e", &exp) == -1)
        return NULL;

    if (bits < 2048)
        return NULL;

    if (!exp)
        exp = json_integer(65537);

    switch (exp ? exp->type : JSON_NULL) {
    case JSON_STRING:
        bn = bn_decode_json(exp);
        if (!bn)
            return NULL;
        break;

    case JSON_INTEGER:
        bn = BN_new();
        if (!bn)
            return NULL;

        if (BN_set_word(bn, json_integer_value(exp)) <= 0)
            return NULL;
        break;

    default:
        break;
    }

    key = RSA_new();
    if (!key)
        return NULL;

    bits = RSA_generate_key_ex(key, bits, bn, NULL);
    if (bits <= 0) {
        RSA_free(key);
        key = NULL;
    }

    return key;
}

static bool
jwk_make_handles(jose_cfg_t *cfg, const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return false;

    return strcmp(kty, "RSA") == 0;
}

static json_t *
jwk_make_execute(jose_cfg_t *cfg, const json_t *jwk)
{
    json_auto_t *key = NULL;
    RSA *rsa = NULL;

    if (!jwk_make_handles(cfg, jwk))
        return NULL;

    rsa = mkrsa(jwk);
    if (!rsa)
        return NULL;

    key = jose_openssl_jwk_from_RSA(cfg, rsa);
    RSA_free(rsa);
    if (!key)
        return NULL;

    return json_pack("{s:[s,s],s:O}", "del", "bits", "e", "upd", key);
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
