/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"
#include "b64.h"
#include "bn.h"

#include <openssl/objects.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static const char *jwkprv[] = {
    "k", "d", "p", "q", "dp", "dq", "qi", "oth", NULL
};

json_t *
jose_jwk_from_key(const jose_key_t *key)
{
    return json_pack("{s:s, s:o}",
                     "kty", "oct",
                     "k", jose_b64_encode_key(key));
}

json_t *
jose_jwk_from_ec(const EC_KEY *key)
{
    const EC_GROUP *grp = NULL;
    const EC_POINT *pub = NULL;
    const BIGNUM *prv = NULL;
    json_t *jwk = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int len = 0;

    if (!key)
        return NULL;

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
        BN_CTX *ctx = NULL;

        x = BN_new();
        y = BN_new();
        if (!x || !y)
            goto error;

        ctx = BN_CTX_new();
        if (!ctx)
            goto error;

        if (EC_POINT_get_affine_coordinates_GFp(grp, pub, x, y, ctx) < 0) {
            BN_CTX_free(ctx);
            goto error;
        }
        BN_CTX_free(ctx);

        if (json_object_set_new(jwk, "x", bn_to_json(x, len)) == -1)
            goto error;

        if (json_object_set_new(jwk, "y", bn_to_json(y, len)) == -1)
            goto error;
    }

    if (prv && json_object_set_new(jwk, "d", bn_to_json(prv, len)) == -1)
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

json_t *
jose_jwk_from_rsa(const RSA *key)
{
    if (!key || !key->n || !key->e)
        return NULL;

    if (key->d && key->p && key->q && key->dmp1 && key->dmq1 && key->iqmp) {
        return json_pack(
            "{s:s,s:o,s:o,s:o,s:o,s:o,s:o,s:o,s:o}",
            "kty", "RSA",
            "n", bn_to_json(key->n, 0),
            "e", bn_to_json(key->e, 0),
            "d", bn_to_json(key->d, 0),
            "p", bn_to_json(key->p, 0),
            "q", bn_to_json(key->q, 0),
            "dp", bn_to_json(key->dmp1, 0),
            "dq", bn_to_json(key->dmq1, 0),
            "qi", bn_to_json(key->iqmp, 0)
        );
    }

    return json_pack(
        "{s:s,s:o,s:o}",
        "kty", "RSA",
        "n", bn_to_json(key->n, 0),
        "e", bn_to_json(key->e, 0)
    );
}

json_t *
jose_jwk_copy(const json_t *jwk, bool prv)
{
    json_t *out = NULL;

    if (!json_is_object(jwk))
        return NULL;

    out = json_deep_copy(jwk);
    if (!out)
        return NULL;

    for (size_t i = 0; !prv && jwkprv[i]; i++) {
        if (!json_object_get(out, jwkprv[i]))
            continue;

        if (json_object_del(out, jwkprv[i]) != -1)
            continue;

        json_decref(out);
        return NULL;
    }

    return out;
}

jose_key_t *
jose_jwk_to_key(const json_t *jwk)
{
    const char *kty = NULL;
    const json_t *k = NULL;

    if (json_unpack((json_t *) jwk, "{s:s, s:o}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    return jose_b64_decode_key(k);
}

EC_KEY *
jose_jwk_to_ec(const json_t *jwk)
{
    const json_t *tmp = NULL;
    int nid = NID_undef;
    EC_POINT *p = NULL;
    EC_KEY *key = NULL;
    BN_CTX *ctx = NULL;
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
        prv = bn_from_json(tmp);
        if (!prv)
            goto error;

        if (EC_KEY_set_private_key(key, prv) < 0)
            goto error;
    }

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    if (json_is_string(json_object_get(jwk, "x")) &&
        json_is_string(json_object_get(jwk, "y"))) {
        EC_POINT *pnt = NULL;

        x = bn_from_json(json_object_get(jwk, "x"));
        y = bn_from_json(json_object_get(jwk, "y"));
        if (!x || !y)
            goto error;

        pnt = EC_POINT_new(EC_KEY_get0_group(key));
        if (!pnt)
            goto error;

        if (EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(key),
                                                pnt, x, y, ctx) < 0) {
            EC_POINT_free(pnt);
            goto error;
        }

        if (EC_KEY_set_public_key(key, pnt) < 0) {
            EC_POINT_free(pnt);
            goto error;
        }

        EC_POINT_free(pnt);
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
    BN_CTX_free(ctx);
    BN_free(prv);
    BN_free(x);
    BN_free(y);
    return key;

error:
    EC_KEY_free(key);
    EC_POINT_free(p);
    BN_CTX_free(ctx);
    BN_free(prv);
    BN_free(x);
    BN_free(y);
    return NULL;
}

RSA *
jose_jwk_to_rsa(const json_t *jwk)
{
    const json_t *dp = NULL;
    const json_t *dq = NULL;
    const json_t *qi = NULL;
    const json_t *n = NULL;
    const json_t *e = NULL;
    const json_t *d = NULL;
    const json_t *p = NULL;
    const json_t *q = NULL;
    const char *kty = NULL;
    RSA *rsa = NULL;

    if (json_unpack(
            (json_t *) jwk, "{s:s,s:o,s:o,s?o,s?o,s?o,s?o,s?o,s?o}",
            "kty", &kty, "n", &n, "e", &e, "d", &d, "p", &p,
            "q", &q, "dp", &dp, "dq", &dq, "qi", &qi
        ) != 0)
        return NULL;

    rsa = RSA_new();
    if (!rsa)
        return NULL;

    rsa->n = bn_from_json(n);
    rsa->e = bn_from_json(e);
    if (!rsa->n || !rsa->e) {
        RSA_free(rsa);
        return NULL;
    }

    if (d && p && q && dp && dq && qi) {
        rsa->d = bn_from_json(d);
        rsa->p = bn_from_json(p);
        rsa->q = bn_from_json(q);
        rsa->dmp1 = bn_from_json(dp);
        rsa->dmq1 = bn_from_json(dq);
        rsa->iqmp = bn_from_json(qi);

        if (!rsa->d    ||
            !rsa->p    ||
            !rsa->q    ||
            !rsa->dmp1 ||
            !rsa->dmq1 ||
            !rsa->iqmp) {
            RSA_free(rsa);
            return NULL;
        }
    }

    return rsa;
}
