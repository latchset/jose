/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/openssl.h>
#include <jose/b64.h>
#include <core/core.h>

#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

#include <string.h>

/*
 * This really doesn't belong here, but OpenSSL doesn't (yet) help us.
 *
 * I have submitted a version of this function upstream:
 *   https://github.com/openssl/openssl/pull/1217
 */
static const unsigned char *
EVP_PKEY_get0_hmac(EVP_PKEY *pkey, size_t *len)
{
    ASN1_OCTET_STRING *os = NULL;

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_HMAC)
        return NULL;

    os = EVP_PKEY_get0(pkey);
    *len = os->length;
    return os->data;
}

static json_t *
from_hmac(EVP_PKEY *key)
{
    const uint8_t *buf = NULL;
    json_t *jwk = NULL;
    size_t len = 0;

    buf = EVP_PKEY_get0_hmac(key, &len);
    if (!buf)
        return NULL;

    jwk = json_pack("{s:s}", "kty", "oct");
    if (jwk) {
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
        X = bn_decode_json(x);
        Y = bn_decode_json(y);
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

    switch (core_str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: nid = NID_X9_62_prime256v1; break;
    case 1: nid = NID_secp384r1; break;
    case 2: nid = NID_secp521r1; break;
    default: return NULL;
    }

    key = EC_KEY_new_by_curve_name(nid);
    if (!key)
        return NULL;

    if (d) {
        D = bn_decode_json(d);
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

    rsa->n = bn_decode_json(n);
    rsa->e = bn_decode_json(e);
    if (!rsa->n || !rsa->e)
        goto egress;

    if (d && p && q && dp && dq && qi) {
        rsa->d = bn_decode_json(d);
        rsa->p = bn_decode_json(p);
        rsa->q = bn_decode_json(q);
        rsa->dmp1 = bn_decode_json(dp);
        rsa->dmq1 = bn_decode_json(dq);
        rsa->iqmp = bn_decode_json(qi);

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
    EVP_PKEY *key = NULL;
    uint8_t *buf = NULL;
    size_t len = 0;

    buf = jose_b64_decode_buf_json(json_object_get(jwk, "k"), &len);
    if (!buf)
        return NULL;

    key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf, len);

    memset(buf, 0, len);
    free(buf);
    return key;
}

json_t *
jose_openssl_jwk_from_key(EVP_PKEY *key, jose_jwk_type_t type)
{
    if (!key)
        return NULL;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        return type & JOSE_JWK_TYPE_OCT ? from_hmac(key) : NULL;
    case EVP_PKEY_RSA:
        return type & JOSE_JWK_TYPE_RSA ? from_rsa(key->pkey.rsa) : NULL;
    case EVP_PKEY_EC:
        return type & JOSE_JWK_TYPE_EC ? from_ec(key->pkey.ec) : NULL;
    default:
        return NULL;
    }
}

EVP_PKEY *
jose_openssl_jwk_to_key(const json_t *jwk, jose_jwk_type_t type)
{
    const char *kty = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    switch (core_str2enum(kty, "oct", "RSA", "EC", NULL)) {
    case 0: return type & JOSE_JWK_TYPE_OCT ? to_hmac(jwk) : NULL;
    case 1: return type & JOSE_JWK_TYPE_RSA ? to_rsa(jwk) : NULL;
    case 2: return type & JOSE_JWK_TYPE_EC ? to_ec(jwk) : NULL;
    default: return NULL;
    }
}
