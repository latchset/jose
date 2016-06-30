/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../core.h"
#include "../jwk.h"
#include "misc.h"

static bool
generate(json_t *jwk)
{
    const char *crv = NULL;
    int nid = NID_undef;
    json_t *tmp = NULL;
    EC_KEY *key = NULL;

    if (json_unpack(jwk, "{s:s}", "crv", &crv) == -1)
        return false;

    switch (core_str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: nid = NID_X9_62_prime256v1; break;
    case 1: nid = NID_secp384r1; break;
    case 2: nid = NID_secp521r1; break;
    default: return false;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return false;

    if (EC_KEY_generate_key(key) <= 0) {
        EC_KEY_free(key);
        return false;
    }

    tmp = from_ec(key);
    EC_KEY_free(key);

    if (json_object_update(jwk, tmp) == -1) {
        json_decref(tmp);
        return false;
    }

    json_decref(tmp);
    return true;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .kty = "EC",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
