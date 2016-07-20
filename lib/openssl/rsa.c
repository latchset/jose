/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/jwk.h>
#include <jose/openssl.h>

#include <openssl/rsa.h>

static RSA *
mkrsa(const json_t *jwk)
{
    json_t *exp = NULL;
    BIGNUM *bn = NULL;
    RSA *key = NULL;
    int bits = 2048;

    if (json_unpack((json_t *) jwk, "{s?i,s?O}",
                    "bits", &bits, "e", &exp) == -1)
        return NULL;

    if (bits < 2048) {
        json_decref(exp);
        return NULL;
    }

    if (!exp)
        exp = json_integer(65537);

    switch (exp ? exp->type : JSON_NULL) {
    case JSON_STRING:
        bn = bn_decode_json(exp);
        if (!bn)
            break;

        key = RSA_new();
        if (!key)
            break;

        bits = RSA_generate_key_ex(key, bits, bn, NULL);
        if (bits <= 0) {
            RSA_free(key);
            key = NULL;
        }
        break;

    case JSON_INTEGER:
        key = RSA_generate_key(bits, json_integer_value(exp), NULL, NULL);
        break;

    default:
        break;
    }

    json_decref(exp);
    BN_free(bn);
    return key;
}

static bool
generate(json_t *jwk)
{
    json_t *tmp = NULL;
    RSA *rsa = NULL;
    bool ret = false;

    rsa = mkrsa(jwk);
    if (!rsa)
        return false;

    tmp = jose_openssl_jwk_from_RSA(rsa);
    RSA_free(rsa);
    if (!tmp)
        return false;

    if (json_object_get(jwk, "bits") && json_object_del(jwk, "bits") == -1)
        goto egress;

    if (json_object_get(jwk, "e") && json_object_del(jwk, "e") == -1)
        goto egress;

    ret = json_object_update_missing(jwk, tmp) == 0;

egress:
    json_decref(tmp);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .kty = "RSA",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
