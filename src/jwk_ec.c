/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "json.h"
#include <openssl/objects.h>
#include <string.h>

json_t *
jose_jwk_from_ec(const EC_KEY *key, BN_CTX *ctx)
{
    const EC_GROUP *grp = NULL;
    const EC_POINT *pub = NULL;
    const BIGNUM *prv = NULL;
    json_t *jwk = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int len = 0;

    jwk = json_object();
    if (!jwk)
        return NULL;

    if (json_object_set_new(jwk, "kty", json_string("EC")) == -1)
        goto error;

    grp = EC_KEY_get0_group(key);
    if (!grp)
        goto error;

    len = (EC_GROUP_get_degree(grp) + 7) / 8;

    switch (EC_GROUP_get_curve_name(grp)) {
    case NID_X9_62_prime256v1:
        if (json_object_set_new(jwk, "crv", json_string("P-256")) == -1)
            goto error;
        break;

    case NID_secp384r1:
        if (json_object_set_new(jwk, "crv", json_string("P-384")) == -1)
            goto error;
        break;

    case NID_secp521r1:
        if (json_object_set_new(jwk, "crv", json_string("P-521")) == -1)
            goto error;
        break;

    default:
        goto error;
    }

    pub = EC_KEY_get0_public_key(key);
    prv = EC_KEY_get0_private_key(key);
    if (!pub && !prv)
        goto error;

    if (pub) {
        x = BN_new();
        y = BN_new();
        if (!x || !y)
            goto error;

        if (EC_POINT_get_affine_coordinates_GFp(grp, pub, x, y, ctx) < 0)
            goto error;

        if (json_object_set_new(jwk, "x", json_from_bn(x, len)) == -1)
            goto error;

        if (json_object_set_new(jwk, "y", json_from_bn(y, len)) == -1)
            goto error;
    }

    if (prv && json_object_set_new(jwk, "d", json_from_bn(prv, len)) == -1)
        goto error;

    BN_free(x);
    BN_free(y);
    return jwk;

error:
    BN_free(x);
    BN_free(y);
    json_decref(jwk);
    return NULL;
}

EC_KEY *
jose_jwk_to_ec(const json_t *jwk, BN_CTX *ctx)
{
    const json_t *tmp = NULL;
    int nid = NID_undef;
    EC_POINT *p = NULL;
    EC_KEY *key = NULL;
    BIGNUM *prv = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    tmp = json_object_get(jwk, "kty");
    if (!json_is_string(tmp) || strcmp(json_string_value(tmp), "EC") != 0)
        return NULL;

    tmp = json_object_get(jwk, "crv");
    if (!json_is_string(tmp))
        return NULL;
    else if (strcmp(json_string_value(tmp), "P-256") == 0)
        nid = NID_X9_62_prime256v1;
    else if (strcmp(json_string_value(tmp), "P-384") == 0)
        nid = NID_secp384r1;
    else if (strcmp(json_string_value(tmp), "P-521") == 0)
        nid = NID_secp521r1;
    else
        return NULL;

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return NULL;

    tmp = json_object_get(jwk, "d");
    if (json_is_string(tmp)) {
        prv = json_to_bn(tmp);
        if (!prv)
            goto error;

        if (EC_KEY_set_private_key(key, prv) < 0) {
            goto error;
        }
    }

    if (json_is_string(json_object_get(jwk, "x")) &&
        json_is_string(json_object_get(jwk, "y"))) {
        x = json_to_bn(json_object_get(jwk, "x"));
        y = json_to_bn(json_object_get(jwk, "y"));
        if (!x || !y)
            goto error;

        if (EC_KEY_set_public_key_affine_coordinates(key, x, y) < 0)
            goto error;
    } else if (prv) {
        p = EC_POINT_new(EC_KEY_get0_group(key));
        if (!p)
            goto error;

        if (EC_POINT_mul(EC_KEY_get0_group(key), p, prv, NULL, NULL, ctx) < 0)
            goto error;

        if (EC_KEY_set_public_key(key, p) < 0)
            goto error;
    } else {
        goto error;
    }

    if (EC_KEY_check_key(key) == 0)
        goto error;

    EC_POINT_free(p);
    BN_free(prv);
    BN_free(x);
    BN_free(y);
    return key;

error:
    EC_KEY_free(key);
    EC_POINT_free(p);
    BN_free(prv);
    BN_free(x);
    BN_free(y);
    return NULL;
}

