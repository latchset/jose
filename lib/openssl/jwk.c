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
#include <jose/openssl.h>
#include <jose/b64.h>
#include <jose/jwk.h>

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

json_t *
jose_openssl_jwk_from_EVP_PKEY(EVP_PKEY *key)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        buf = EVP_PKEY_get0_hmac(key, &len);
        if (!buf)
            return NULL;

        return json_pack("{s:s,s:o}", "kty", "oct", "k",
                         jose_b64_encode_json(buf, len));

    case EVP_PKEY_RSA:
        return jose_openssl_jwk_from_RSA(key->pkey.rsa);

    case EVP_PKEY_EC:
        return jose_openssl_jwk_from_EC_KEY(key->pkey.ec);
    default: return NULL;
    }
}

json_t *
jose_openssl_jwk_from_RSA(const RSA *key)
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

json_t *
jose_openssl_jwk_from_EC_KEY(const EC_KEY *key)
{
    return jose_openssl_jwk_from_EC_POINT(
        EC_KEY_get0_group(key),
        EC_KEY_get0_public_key(key),
        EC_KEY_get0_private_key(key)
    );
}

json_t *
jose_openssl_jwk_from_EC_POINT(const EC_GROUP *grp, const EC_POINT *pub,
                               const BIGNUM *prv)
{
    const char *crv = NULL;
    json_t *jwk = NULL;
    EC_POINT *p = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int len = 0;

    if (!grp || !pub)
        return NULL;

    len = (EC_GROUP_get_degree(grp) + 7) / 8;

    switch (EC_GROUP_get_curve_name(grp)) {
    case NID_X9_62_prime256v1: crv = "P-256"; break;
    case NID_secp384r1: crv = "P-384"; break;
    case NID_secp521r1: crv = "P-521"; break;
    default: goto egress;
    }

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    if (!pub) {
        if (!prv)
            goto egress;

        pub = p = EC_POINT_new(grp);
        if (!pub)
            goto egress;

        if (EC_POINT_mul(grp, p, prv, NULL, NULL, ctx) < 0)
            goto egress;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y)
        goto egress;

    if (EC_POINT_get_affine_coordinates_GFp(grp, pub, x, y, ctx) < 0)
        goto egress;

    jwk = json_pack("{s:s,s:s,s:o,s:o}", "kty", "EC", "crv", crv,
                    "x", bn_encode_json(x, len), "y", bn_encode_json(y, len));
    if (prv && json_object_set_new(jwk, "d", bn_encode_json(prv, len)) == -1) {
        json_decref(jwk);
        jwk = NULL;
    }

egress:
    EC_POINT_free(p);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);
    return jwk;
}

EVP_PKEY *
jose_openssl_jwk_to_EVP_PKEY(const json_t *jwk)
{
    jose_buf_auto_t *buf = NULL;
    const char *kty = NULL;
    EVP_PKEY *key = NULL;
    EC_KEY *ec = NULL;
    RSA *rsa = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) == -1)
        return NULL;

    switch (str2enum(kty, "EC", "RSA", "oct", NULL)) {
    case 0:
        ec = jose_openssl_jwk_to_EC_KEY(jwk);
        if (!ec)
            return NULL;

        key = EVP_PKEY_new();
        if (key) {
            if (EVP_PKEY_set1_EC_KEY(key, ec) <= 0) {
                EVP_PKEY_free(key);
                EC_KEY_free(ec);
                return NULL;
            }
        }

        EC_KEY_free(ec);
        return key;

    case 1:
        rsa = jose_openssl_jwk_to_RSA(jwk);
        if (!rsa)
            return NULL;

        key = EVP_PKEY_new();
        if (key) {
            if (EVP_PKEY_set1_RSA(key, rsa) <= 0) {
                EVP_PKEY_free(key);
                RSA_free(rsa);
                return NULL;
            }
        }

        RSA_free(rsa);
        return key;

    case 2:
        buf = jose_b64_decode_json(json_object_get(jwk, "k"));
        if (!buf)
            return NULL;

        return EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf->data, buf->size);

    default: return NULL;
    }
}

RSA *
jose_openssl_jwk_to_RSA(const json_t *jwk)
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

    rsa->n = bn_decode_json(n);
    rsa->e = bn_decode_json(e);
    if (!rsa->n || !rsa->e)
        goto error;

    if (d && p && q && dp && dq && qi) {
        rsa->d = bn_decode_json(d);
        rsa->p = bn_decode_json(p);
        rsa->q = bn_decode_json(q);
        rsa->dmp1 = bn_decode_json(dp);
        rsa->dmq1 = bn_decode_json(dq);
        rsa->iqmp = bn_decode_json(qi);

        if (!rsa->d || !rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 ||
            !rsa->iqmp || RSA_blinding_on(rsa, NULL) <= 0)
            goto error;
    }

    return rsa;

error:
    RSA_free(rsa);
    return NULL;
}

EC_KEY *
jose_openssl_jwk_to_EC_KEY(const json_t *jwk)
{
    const char *kty = NULL;
    const char *crv = NULL;
    const json_t *x = NULL;
    const json_t *y = NULL;
    const json_t *d = NULL;
    EC_POINT *pub = NULL;
    int nid = NID_undef;
    EC_KEY *key = NULL;
    BIGNUM *D = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s,s:o,s:o,s?o}", "kty", &kty,
                    "crv", &crv, "x", &x, "y", &y, "d", &d) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str2enum(crv, "P-256", "P-384", "P-521", NULL)) {
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
            goto error;

        if (EC_KEY_set_private_key(key, D) < 0)
            goto error;
    }

    pub = mkpub(EC_KEY_get0_group(key), x, y, D);
    if (!pub)
        goto error;

    if (EC_KEY_set_public_key(key, pub) < 0)
        goto error;

    if (EC_KEY_check_key(key) == 0)
        goto error;

    EC_POINT_free(pub);
    BN_free(D);
    return key;

error:
    EC_POINT_free(pub);
    EC_KEY_free(key);
    BN_free(D);
    return NULL;
}

