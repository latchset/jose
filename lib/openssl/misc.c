/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <string.h>

size_t
str2enum(const char *str, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, str);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && strcmp(str, v) == 0)
            break;
    }

    va_end(ap);
    return i;
}

BIGNUM *
bn_decode(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

BIGNUM *
bn_decode_json(const json_t *json)
{
    uint8_t *buf = NULL;
    BIGNUM *bn = NULL;
    size_t len = 0;

    buf = jose_b64_decode_buf_json(json, &len);
    if (!buf)
        return NULL;

    bn = bn_decode(buf, len);

    memset(buf, 0, len);
    free(buf);
    return bn;
}

bool
bn_encode(const BIGNUM *bn, uint8_t buf[], size_t len)
{
    int bytes = 0;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    bytes = BN_num_bytes(bn);
    if (bytes < 0 || bytes > (int) len)
        return false;

    memset(buf, 0, len);
    return BN_bn2bin(bn, &buf[len - bytes]) > 0;
}

json_t *
bn_encode_json(const BIGNUM *bn, size_t len)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    if ((int) len < BN_num_bytes(bn))
        return false;

    buf = malloc(len);
    if (buf) {
        if (bn_encode(bn, buf, len))
            out = jose_b64_encode_json(buf, len);

        free(buf);
    }

    return out;
}

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

json_t *
from_ec(EC_KEY *key)
{
    const BIGNUM *d = NULL;
    const char *crv = NULL;
    json_t *jwk = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int len = 0;

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
                    "x", bn_encode_json(x, len), "y", bn_encode_json(y, len));
    if (d && json_object_set_new(jwk, "d", bn_encode_json(d, len)) == -1) {
        json_decref(jwk);
        jwk = NULL;
    }

egress:
    BN_free(x);
    BN_free(y);
    return jwk;
}

json_t *
from_rsa(RSA *key)
{
    json_t *jwk = NULL;

    if (!key)
        return NULL;

    if (!key->n || !key->e)
        return NULL;

    if (key->d && key->p && key->q && key->dmp1 && key->dmq1 && key->iqmp) {
        jwk = json_pack(
            "{s:s,s:o,s:o,s:o,s:o,s:o,s:o,s:o,s:o}",
            "kty", "RSA",
            "n", bn_encode_json(key->n, 0),
            "e", bn_encode_json(key->e, 0),
            "d", bn_encode_json(key->d, 0),
            "p", bn_encode_json(key->p, 0),
            "q", bn_encode_json(key->q, 0),
            "dp", bn_encode_json(key->dmp1, 0),
            "dq", bn_encode_json(key->dmq1, 0),
            "qi", bn_encode_json(key->iqmp, 0)
        );
    } else {
        jwk = json_pack(
            "{s:s,s:o,s:o}",
            "kty", "RSA",
            "n", bn_encode_json(key->n, 0),
            "e", bn_encode_json(key->e, 0)
        );
    }

    return jwk;
}
