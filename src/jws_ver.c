/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jws.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>

jose_buf_t *
sign(const char *prot, const char *payl, EVP_PKEY *key, const char *alg);

static bool
verify(const char *prot, const char *payl, EVP_PKEY *key, const char *alg,
       const jose_buf_t *sig)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    const char *req = NULL;
    jose_buf_t *alt = NULL;
    bool ret = false;
    int bytes = 0;
    int pad = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        alt = sign(prot, payl, key, alg);
        if (alt && alt->used == sig->used)
            ret = CRYPTO_memcmp(alt, sig, sig->used) == 0;

        free(alt);
        return ret;

    case EVP_PKEY_RSA:
        /* Note that although RFC 7518 3.3 says we shouldn't use small keys,
         * in the interest of being liberal in the data that we receive, we
         * allow small keys only for verification. */

        switch (str_to_enum(alg, "RS256", "RS384", "RS512",
                            "PS256", "PS384", "PS512", NULL)) {
        case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
        case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
        case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
        case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
        case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
        case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
        default: return false;
        }
        break;

    case EVP_PKEY_EC: {
        const EC_GROUP *grp = NULL;
        ECDSA_SIG ecdsa = {};

        grp = EC_KEY_get0_group(key->pkey.ec);
        if (!grp)
            return false;

        switch (EC_GROUP_get_curve_name(grp)) {
        case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
        case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
        case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
        default: return false;
        }

        if (strcmp(alg, req) != 0)
            return false;

        ecdsa.r = bn_decode(sig->data, sig->used / 2);
        ecdsa.s = bn_decode(&sig->data[sig->used / 2], sig->used / 2);

        alt = jose_buf_new(i2d_ECDSA_SIG(&ecdsa, NULL), false);
        if (!alt)
            return false;

        if (ecdsa.r && ecdsa.s)
            bytes = i2d_ECDSA_SIG(&ecdsa, &(uint8_t *) { alt->data });

        BN_free(ecdsa.r);
        BN_free(ecdsa.s);

        if (bytes <= 0)
            goto egress;

        alt->used = bytes;
        sig = alt;
        break;
    }

    default:
        return false;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto egress;

    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, key) < 0)
        goto egress;

    if (pad != 0 && EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, prot, strlen(prot)) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, ".", 1) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, payl, strlen(payl)) < 0)
        goto egress;

    ret = EVP_DigestVerifyFinal(ctx, sig->data, sig->used) == 1;

egress:
    EVP_MD_CTX_destroy(ctx);
    jose_buf_free(alt);
    return ret;
}

static bool
verify_sig(const char *pay, const json_t *sig, EVP_PKEY *key)
{
    const json_t *prot = NULL;
    const json_t *head = NULL;
    const char *sign = NULL;
    const char *alg = NULL;
    jose_buf_t *buf = NULL;
    json_t *p = NULL;
    bool ret = false;

    if (json_unpack((json_t *) sig, "{s: s, s? o, s? o}", "signature", &sign,
                    "protected", &prot, "header", &head) == -1)
        return false;

    if (!prot && !head)
        return false;

    buf = jose_b64_decode_buf(sign, false);
    if (!buf)
        goto egress;

    p = jose_b64_decode_json_load(prot, 0);
    if (prot && !p)
        goto egress;

    if (json_unpack(p, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) head, "{s: s}", "alg", &alg) == -1)
        goto egress;

    ret = verify(prot ? json_string_value(prot) : "", pay, key, alg, buf);

egress:
    json_decref(p);
    free(buf);
    return ret;
}

bool
jose_jws_verify(const json_t *jws, EVP_PKEY *key)
{
    const json_t *array = NULL;
    const char *payl = NULL;

    if (!key)
        return false;

    if (json_unpack((json_t *) jws, "{s: s}", "payload", &payl) == -1)
        return false;

    /* Verify signatures in general format. */
    array = json_object_get(jws, "signatures");
    if (json_is_array(array) && json_array_size(array) > 0) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *sig = json_array_get(array, i);

            if (verify_sig(payl, sig, key))
                return true;
        }

        return false;
    }

    /* Verify the signature in flattened format. */
    return verify_sig(payl, jws, key);
}

bool
jose_jws_verify_jwk(const json_t *jws, const json_t *jwks, bool all)
{
    const json_t *array = NULL;
    EVP_PKEY *key = NULL;
    bool valid = false;

    if (!jws || !jwks)
        return false;

    if (json_is_array(jwks))
        array = jwks;
    else if (json_is_array(json_object_get(jwks, "keys")))
        array = json_object_get(jwks, "keys");

    if (json_is_array(array)) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *jwk = json_array_get(array, i);

            key = jose_jwk_to_key(jwk);
            valid = jose_jws_verify(jws, key);
            EVP_PKEY_free(key);

            if (valid && !all)
                return true;
            if (!valid && all)
                return false;
        }

        return all && json_array_size(array) > 0;
    }

    key = jose_jwk_to_key(jwks);
    valid = jose_jws_verify(jws, key);
    EVP_PKEY_free(key);
    return valid;
}
