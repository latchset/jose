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

/* The following functions are from OpenSSL 3 code base:
 * - bn_is_three()
 * - check_public_exponent() is ossl_rsa_check_public_exponent(), with
 *   a minor change -- no FIPS check for allowing RSA_3. */
static int bn_is_three(const BIGNUM *bn)
{
    BIGNUM *num = BN_dup(bn);
    int ret = (num != NULL && BN_sub_word(num, 3) && BN_is_zero(num));

    BN_free(num);
    return ret;
}

/* Check exponent is odd, and has a bitlen ranging from [17..256]
 * In practice, it allows odd integers greater than or equal to 65537. 3 is
 * also allowed, for legacy purposes. */
static int check_public_exponent(const BIGNUM* e)
{
    int bitlen;

    /* In OpenSSL 3, RSA_3 is allowed in non-FIPS mode only, for
     * legacy purposes. */
    if (bn_is_three(e)) {
        return 1;
    }
    bitlen = BN_num_bits(e);
    return (BN_is_odd(e) && bitlen > 16 && bitlen < 257);
}

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

    if (!check_public_exponent(bn)) {
        return NULL;
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

static bool
jwk_make_execute(jose_cfg_t *cfg, json_t *jwk)
{
    json_auto_t *key = NULL;
    RSA *rsa = NULL;

    if (!jwk_make_handles(cfg, jwk))
        return false;

    rsa = mkrsa(jwk);
    if (!rsa)
        return false;

    key = jose_openssl_jwk_from_RSA(cfg, rsa);
    RSA_free(rsa);
    if (!key)
        return false;

    if (json_object_get(jwk, "bits") && json_object_del(jwk, "bits") < 0)
        return false;

    if (json_object_get(jwk, "e") && json_object_del(jwk, "e") < 0)
        return false;

    /* The "oth" parameter is optional. */
    copy_val(key, jwk, "oth");

    return copy_val(key, jwk, "n", "e", "p", "d", "q", "dp", "dq", "qi", NULL);
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
