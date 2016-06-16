/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"
#include "b64.h"
#include "lbuf.h"
#include "conv.h"

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static const char *jwkprv[] = {
    "k", "d", "p", "q", "dp", "dq", "qi", "oth", NULL
};

static bool
getxyd(const EC_KEY *key, BIGNUM **x, BIGNUM **y, const BIGNUM **d)
{
    const EC_GROUP *grp = NULL;
    const EC_POINT *pub = NULL;
    EC_POINT *p = NULL;
    BN_CTX *ctx = NULL;

    grp = EC_KEY_get0_group(key);
    if (!grp)
        return false;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    pub = EC_KEY_get0_public_key(key);
    *d = EC_KEY_get0_private_key(key);
    if (!pub) {
        if (!*d)
            goto error;

        pub = p = EC_POINT_new(grp);
        if (!pub)
            goto error;

        if (EC_POINT_mul(grp, p, *d, NULL, NULL, ctx) < 0)
            goto error;
    }

    *x = BN_new();
    *y = BN_new();
    if (!*x || !*y)
        goto error;

    if (EC_POINT_get_affine_coordinates_GFp(grp, pub, *x, *y, ctx) < 0)
        goto error;

    EC_POINT_free(p);
    BN_CTX_free(ctx);
    return true;

error:
    BN_free(*x); *x = NULL;
    BN_free(*y); *y = NULL;
    EC_POINT_free(p);
    BN_CTX_free(ctx);
    return false;
}

static json_t *
from_ec(EVP_PKEY *pkey, bool prv)
{
    const BIGNUM *d = NULL;
    const char *crv = NULL;
    EC_KEY *key = NULL;
    json_t *jwk = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int len = 0;

    if (!pkey)
        return NULL;

    key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!key)
        return NULL;

    len = (EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key))) {
    case NID_X9_62_prime256v1: crv = "P-256"; break;
    case NID_secp384r1: crv = "P-384"; break;
    case NID_secp521r1: crv = "P-521"; break;
    default: goto egress;
    }

    if (!getxyd(key, &x, &y, &d))
        goto egress;

    jwk = json_pack("{s:s,s:s,s:o,s:o}", "kty", "EC", "crv", crv,
                    "x", bn_to_json(x, len), "y", bn_to_json(y, len));
    if (d && prv && json_object_set_new(jwk, "d", bn_to_json(d, len)) == -1) {
        json_decref(jwk);
        jwk = NULL;
    }

egress:
    EC_KEY_free(key);
    BN_free(x);
    BN_free(y);
    return jwk;
}

static json_t *
from_rsa(EVP_PKEY *pkey, bool prv)
{
    json_t *jwk = NULL;
    RSA *key = NULL;

    if (!pkey)
        return NULL;

    key = EVP_PKEY_get1_RSA(pkey);
    if (!key)
        return NULL;

    if (!key->n || !key->e)
        goto egress;

    if (prv && key->d && key->p && key->q &&
        key->dmp1 && key->dmq1 && key->iqmp) {
        jwk = json_pack(
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
    } else {
        jwk = json_pack(
            "{s:s,s:o,s:o}",
            "kty", "RSA",
            "n", bn_to_json(key->n, 0),
            "e", bn_to_json(key->e, 0)
        );
    }

egress:
    RSA_free(key);
    return jwk;
}

static json_t *
from_hmac(EVP_PKEY *key, bool prv)
{
    const uint8_t *buf = NULL;
    json_t *jwk = NULL;
    size_t len = 0;

    buf = EVP_PKEY_get0_hmac(key, &len);
    if (!buf)
        return NULL;

    jwk = json_pack("{s:s}", "kty", "oct");
    if (jwk && prv) {
        json_t *k = jose_b64_encode_json(buf, len);
        if (json_object_set_new(jwk, "k", k) == -1) {
            json_decref(jwk);
            return NULL;
        }
    }

    return jwk;
}

static EC_POINT *
mkpub(const EC_GROUP *grp, const json_t *x, const json_t *y, const BIGNUM *D)
{
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *X = NULL;
    BIGNUM *Y = NULL;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    pub = EC_POINT_new(grp);
    if (!pub)
        goto error;

    if (x && y) {
        X = bn_from_json(x);
        Y = bn_from_json(y);
        if (!X || !Y)
            goto error;

        if (EC_POINT_set_affine_coordinates_GFp(grp, pub, X, Y, ctx) < 0)
            goto error;
    } else if (D) {
        if (EC_POINT_mul(grp, pub, D, NULL, NULL, ctx) < 0)
            goto error;
    } else {
        goto error;
    }

    BN_CTX_free(ctx);
    BN_free(X);
    BN_free(Y);
    return pub;

error:
    EC_POINT_free(pub);
    BN_CTX_free(ctx);
    BN_free(X);
    BN_free(Y);
    return NULL;
}

static EVP_PKEY *
to_ec(const json_t *jwk)
{
    const char *kty = NULL;
    const char *crv = NULL;
    const json_t *x = NULL;
    const json_t *y = NULL;
    const json_t *d = NULL;
    EVP_PKEY *pkey = NULL;
    EC_POINT *pub = NULL;
    int nid = NID_undef;
    EC_KEY *key = NULL;
    BIGNUM *D = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s,s:o,s:o,s?o}", "kty", &kty,
                    "crv", &crv, "x", &x, "y", &y, "d", &d) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str_to_enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: nid = NID_X9_62_prime256v1; break;
    case 1: nid = NID_secp384r1; break;
    case 2: nid = NID_secp521r1; break;
    default: return NULL;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return NULL;

    if (d) {
        D = bn_from_json(d);
        if (!D)
            goto egress;

        if (EC_KEY_set_private_key(key, D) < 0)
            goto egress;
    }

    pub = mkpub(EC_KEY_get0_group(key), x, y, D);
    if (!pub)
        goto egress;

    if (EC_KEY_set_public_key(key, pub) < 0)
        goto egress;

    if (EC_KEY_check_key(key) == 0)
        goto egress;

    pkey = EVP_PKEY_new();
    if(!pkey)
        goto egress;

    if (EVP_PKEY_set1_EC_KEY(pkey, key) < 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

egress:
    EC_POINT_free(pub);
    EC_KEY_free(key);
    BN_free(D);
    return pkey;
}

static EVP_PKEY *
to_rsa(const json_t *jwk)
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
    EVP_PKEY *pkey = NULL;
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
    if (!rsa->n || !rsa->e)
        goto egress;

    if (d && p && q && dp && dq && qi) {
        rsa->d = bn_from_json(d);
        rsa->p = bn_from_json(p);
        rsa->q = bn_from_json(q);
        rsa->dmp1 = bn_from_json(dp);
        rsa->dmq1 = bn_from_json(dq);
        rsa->iqmp = bn_from_json(qi);

        if (!rsa->d || !rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 ||
            !rsa->iqmp || RSA_blinding_on(rsa, NULL) <= 0)
            goto egress;
    }

    pkey = EVP_PKEY_new();
    if (!pkey)
        goto egress;

    if (EVP_PKEY_set1_RSA(pkey, rsa) < 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

egress:
    RSA_free(rsa);
    return pkey;
}

static EVP_PKEY *
to_hmac(const json_t *jwk)
{
    const char *k = NULL;
    EVP_PKEY *key = NULL;
    lbuf_t *lbuf = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "k", &k) == -1)
        return NULL;

    lbuf = lbuf_new(jose_b64_dlen(strlen(k)));
    if (!lbuf)
        return NULL;

    if (jose_b64_decode(k, lbuf->buf))
        key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, lbuf->buf, lbuf->len);

    lbuf_free(lbuf);
    return key;
}

json_t *
jose_jwk_from_key(EVP_PKEY *key, bool prv)
{
    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC: return from_hmac(key, prv);
    case EVP_PKEY_RSA: return from_rsa(key, prv);
    case EVP_PKEY_EC: return from_ec(key, prv);
    default: return NULL;
    }
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

EVP_PKEY *
jose_jwk_to_key(const json_t *jwk)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    switch (str_to_enum(kty, "oct", "RSA", "EC", NULL)) {
    case 0: return to_hmac(jwk);
    case 1: return to_rsa(jwk);
    case 2: return to_ec(jwk);
    default: return NULL;
    }
}
