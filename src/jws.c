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

static bool
add_sig(json_t *jws, json_t *head, const char *prot,
        const uint8_t *sig, size_t len)
{
    json_t *signatures = NULL;
    json_t *signature = NULL;
    json_t *protected = NULL;
    json_t *header = NULL;

    if (json_object_size(head) == 0 && (!prot || strlen(prot) == 0))
        return false;

    if (json_unpack(jws, "{s? o, s? o, s? o, s? o}",
                    "signatures", &signatures, "signature", &signature,
                    "protected", &protected, "header", &header) == -1)
        return false;

    if (signatures) {
        if (!json_is_array(signatures))
            return false;

        if (json_array_size(signatures) == 0) {
            if (json_object_del(jws, "signatures") == -1)
                return false;

            signatures = NULL;
        }
    }

    /* If we have a sig in flattened format, migrate to general format. */
    if (signature) {
        json_t *obj = NULL;

        if (!signatures) {
            signatures = json_array();
            if (json_object_set_new(jws, "signatures", signatures) == -1)
                return false;
        }

        obj = json_pack("{s: O}", "signature", signature);
        if (json_array_append_new(signatures, obj) == -1)
            return false;

        if (json_object_del(jws, "signature") == -1)
            return false;

        if (protected) {
            if (json_object_set(obj, "protected", protected) == -1)
                return false;

            if (json_object_del(jws, "protected") == -1)
                return false;
        }

        if (header) {
            if (json_object_set(obj, "header", header) == -1)
                return false;

            if (json_object_del(jws, "header") == -1)
                return false;
        }
    }

    /* If we have some signatures already, append to the array. */
    if (signatures) {
        json_t *obj = NULL;

        obj = json_object();
        if (json_array_append_new(signatures, obj) == -1)
            return false;

        jws = obj;
    }

    signature = jose_b64_encode_json(sig, len);
    if (json_object_set_new(jws, "signature", signature) < 0)
        return false;

    if (prot && json_object_set_new(jws, "protected", json_string(prot)) < 0)
        return false;

    if (json_object_size(head) > 0 &&
        json_object_set(jws, "header", head) < 0)
        return false;

    return true;
}

static const char *
suggest(EVP_PKEY *key)
{
    int len = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        if (!EVP_PKEY_get_hmac(key, &len))
            return NULL;

        len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;

        switch (len & (SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH)) {
        case SHA512_DIGEST_LENGTH: return "HS512";
        case SHA384_DIGEST_LENGTH: return "HS384";
        case SHA256_DIGEST_LENGTH: return "HS256";
        default: return NULL;
        }

    case EVP_PKEY_RSA:
        len = RSA_size(key->pkey.rsa) / 8;

        len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;

        switch (len & (SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH)) {
        case SHA512_DIGEST_LENGTH: return "RS512";
        case SHA384_DIGEST_LENGTH: return "RS384";
        case SHA256_DIGEST_LENGTH: return "RS256";
        default: return NULL;
        }

    case EVP_PKEY_EC:
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
        case NID_X9_62_prime256v1: return "ES256";
        case NID_secp384r1:        return "ES384";
        case NID_secp521r1:        return "ES512";
        default: return NULL;
        }

    default:
        return NULL;
    }
}

static uint8_t *
sign(const char *prot, const char *payl, EVP_PKEY *key,
     const char *alg, size_t *len)
{
    ECDSA_SIG *ecdsa = NULL;
    const EVP_MD *md = NULL;
    const char *req = NULL;
    EVP_MD_CTX *ctx = NULL;
    uint8_t *sig = NULL;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        switch (string_to_enum(alg, false, "HS256", "HS384", "HS512", NULL)) {
        case 0: md = EVP_sha256(); break;
        case 1: md = EVP_sha384(); break;
        case 2: md = EVP_sha512(); break;
        default: return NULL;
        }
        break;

    case EVP_PKEY_RSA:
        /* Don't use small keys. RFC 7518 3.3 */
        if (RSA_size(key->pkey.rsa) < 2048 / 8)
            return NULL;

        switch (string_to_enum(alg, false, "RS256", "RS384", "RS512", NULL)) {
        case 0: md = EVP_sha256(); break;
        case 1: md = EVP_sha384(); break;
        case 2: md = EVP_sha512(); break;
        default: return NULL;
        }
        break;

    case EVP_PKEY_EC:
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
        case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
        case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
        case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
        default: return NULL;
        }

        if (strcmp(alg, req) != 0)
            return NULL;
        break;

    default:
        return NULL;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return NULL;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, prot, strlen(prot)) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, ".", 1) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, payl, strlen(payl)) < 0)
        goto error;

    if (EVP_DigestSignFinal(ctx, NULL, len) < 0)
        goto error;

    sig = malloc(*len);
    if (!sig)
        goto error;

    if (EVP_DigestSignFinal(ctx, sig, len) < 0)
        goto error;

    /* We have to special-case ECDSA signatures: the format is different. */
    if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
        const EC_GROUP *grp = NULL;

        ecdsa = d2i_ECDSA_SIG(NULL, &(const uint8_t *) { sig }, *len);
        if (!ecdsa)
            goto error;

        grp = EC_KEY_get0_group(key->pkey.ec);
        if (!grp)
            goto error;
        *len = (EC_GROUP_get_degree(grp) + 7) / 8 * 2;

        free(sig);
        sig = malloc(*len);
        if (!sig)
            goto error;

        if (!bn_to_buf(ecdsa->r, sig, *len / 2))
            goto error;

        if (!bn_to_buf(ecdsa->s, &sig[*len / 2], *len / 2))
            goto error;
    }

    EVP_MD_CTX_destroy(ctx);
    ECDSA_SIG_free(ecdsa);
    return sig;

error:
    EVP_MD_CTX_destroy(ctx);
    ECDSA_SIG_free(ecdsa);
    free(sig);
    return NULL;
}

static bool
verify(const char *prot, const char *payl,
       EVP_PKEY *key, const char *alg,
       const uint8_t sig[], size_t len)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    const char *req = NULL;
    ECDSA_SIG ecdsa = {};
    uint8_t *alt = NULL;
    bool ret = false;
    size_t slen = 0;
    int bytes = 0;

    fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        alt = sign(prot, payl, key, alg, &slen);
        if (alt && len == slen)
            ret = CRYPTO_memcmp(alt, sig, len) == 0;

        free(alt);
        return ret;

    case EVP_PKEY_RSA:
        /* Note that although RFC 7518 3.3 says we shouldn't use small keys,
         * in the interest of being liberal in the data that we receive, we
         * allow small keys only for verification. */

        switch (string_to_enum(alg, false, "RS256", "RS384", "RS512", NULL)) {
        case 0: md = EVP_sha256(); break;
        case 1: md = EVP_sha384(); break;
        case 2: md = EVP_sha512(); break;
        default: return false;
        }
        break;

    case EVP_PKEY_EC:
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
        case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
        case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
        case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
        default: return NULL;
        }

        if (strcmp(alg, req) != 0)
            return NULL;

        ecdsa.r = bn_from_buf(sig, len / 2);
        ecdsa.s = bn_from_buf(&sig[len / 2], len / 2);

        if (ecdsa.r && ecdsa.s)
            bytes = i2d_ECDSA_SIG(&ecdsa, &alt);

        BN_free(ecdsa.r);
        BN_free(ecdsa.s);

        sig = alt;
        len = bytes;
        if (bytes <= 0)
            goto egress;
        break;

    default:
        return false;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto egress;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, key) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, prot, strlen(prot)) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, ".", 1) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, payl, strlen(payl)) < 0)
        goto egress;

    ret = EVP_DigestVerifyFinal(ctx, sig, len) == 1;

egress:
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(alt);
    return ret;
}

json_t *
jose_jws_from_compact(const char *jws)
{
    return compact_to_obj(jws, "protected", "payload", "signature", NULL);
}

char *
jose_jws_to_compact(const json_t *jws)
{
    const char *signature = NULL;
    const char *protected = NULL;
    const char *payload = NULL;
    const char *header = NULL;
    char *out = NULL;

    if (json_unpack((json_t *) jws, "{s: s, s: s, s: s, s? s}",
                    "payload", &payload,
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1 &&
        json_unpack((json_t *) jws, "{s: s, s: [{s: s, s: s, s: s, s? s}!]}",
                    "payload", &payload,
                    "signatures",
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1)
        return NULL;

    if (header)
        return NULL;

    asprintf(&out, "%s.%s.%s", protected, payload, signature);
    return out;
}

bool
jose_jws_sign(json_t *jws, const json_t *head, const json_t *prot,
              EVP_PKEY *key)
{
    const char *payload = NULL;
    const char *alg = NULL;
    uint8_t *sig = NULL;
    json_t *h = NULL;
    json_t *p = NULL;
    json_t *e = NULL;
    bool ret = false;
    size_t len = 0;

    if (!key)
        return false;

    if (json_unpack(jws, "{s:s}", "payload", &payload) == -1)
        return false;

    h = json_deep_copy(head);
    if (head && !h)
        goto egress;

    p = json_deep_copy(prot);
    if (prot && !p)
        goto egress;

    /* Look up the algorithm, or try to detect it. */
    if (json_unpack(p, "{s:s}", "alg", &alg) == -1 &&
        json_unpack(h, "{s:s}", "alg", &alg) == -1) {
        alg = suggest(key);
        if (!alg)
            goto egress;

        if (!h && !p)
            p = json_object();

        if (json_object_set_new(p ? p : h, "alg", json_string(alg)) == -1)
            goto egress;
    }

    if (json_object_size(p) > 0) {
        e = jose_b64_encode_json_dump(p, JSON_SORT_KEYS | JSON_COMPACT);
        if (!json_is_string(e))
            goto egress;
    }

    sig = sign(json_string_value(e), payload, key, alg, &len);
    if (sig)
        ret = add_sig(jws, h, json_string_value(e), sig, len);

    free(sig);

egress:
    json_decref(h);
    json_decref(p);
    json_decref(e);
    return ret;
}

bool
jose_jws_sign_jwk(json_t *jws, const json_t *head, const json_t *prot,
                  const json_t *jwks, jose_jws_flags_t flags)
{
    const json_t *array = NULL;
    EVP_PKEY *key = NULL;
    json_t *h = NULL;
    json_t *p = NULL;
    bool ret = false;

    if (!jws || !jwks)
        return false;

    if (json_is_array(jwks))
        array = jwks;
    else if (json_is_array(json_object_get(jwks, "keys")))
        array = json_object_get(jwks, "keys");

    if (json_is_array(array)) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *jwk = json_array_get(array, i);

            if (!jose_jws_sign_jwk(jws, head, prot, jwk, flags))
                return false;
        }

        return json_array_size(array) > 0;
    }

    h = json_deep_copy(head);
    if (head && !h)
        goto egress;

    if (!h && (flags & (JOSE_JWS_FLAGS_JWK_HEAD | JOSE_JWS_FLAGS_KID_HEAD)))
        h = json_object();

    p = json_deep_copy(prot);
    if (prot && !p)
        goto egress;

    if (!p && (flags & (JOSE_JWS_FLAGS_JWK_PROT | JOSE_JWS_FLAGS_KID_PROT)))
        p = json_object();

    if (flags & JOSE_JWS_FLAGS_JWK_HEAD && !json_object_get(h, "jwk")) {
        json_t *copy = jose_jwk_copy(jwks, false);
        if (json_object_set_new(h, "jwk", copy) == -1)
            goto egress;
    }

    if (flags & JOSE_JWS_FLAGS_JWK_PROT && !json_object_get(p, "jwk")) {
        json_t *copy = jose_jwk_copy(jwks, false);
        if (json_object_set_new(p, "jwk", copy) == -1)
            goto egress;
    }

    if (flags & JOSE_JWS_FLAGS_KID_HEAD && !json_object_get(h, "kid")) {
        json_t *kid = json_object_get(jwks, "kid");
        if (kid && json_object_set(h, "kid", kid) == -1)
            goto egress;
    }

    if (flags & JOSE_JWS_FLAGS_KID_PROT && !json_object_get(p, "kid")) {
        json_t *kid = json_object_get(jwks, "kid");
        if (kid && json_object_set(p, "kid", kid) == -1)
            goto egress;
    }

    key = jose_jwk_to_key(jwks);
    ret = jose_jws_sign(jws, h, p, key);

egress:
    EVP_PKEY_free(key);
    json_decref(h);
    json_decref(p);
    return ret;
}

static bool
do_verify(const char *pay, const json_t *sig, EVP_PKEY *key)
{
    const json_t *prot = NULL;
    const json_t *head = NULL;
    const char *sign = NULL;
    const char *alg = NULL;
    uint8_t *buf = NULL;
    json_t *p = NULL;
    bool ret = false;
    size_t len = 0;

    if (json_unpack((json_t *) sig, "{s: s, s? o, s? o}", "signature", &sign,
                    "protected", &prot, "header", &head) == -1)
        return false;

    if (!prot && !head)
        return false;

    len = jose_b64_dlen(strlen(sign));
    buf = malloc(len);
    if (!buf)
        return false;

    if (!jose_b64_decode(sign, buf))
        goto egress;

    p = jose_b64_decode_json_load(prot, 0);
    if (prot && !p)
        goto egress;

    if (json_unpack(p, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) head, "{s: s}", "alg", &alg) == -1)
        goto egress;

    fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
    ret = verify(prot ? json_string_value(prot) : "", pay, key, alg, buf, len);
    fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);

egress:
    json_decref(p);
    free(buf);
    return ret;
}

bool __attribute__((warn_unused_result))
jose_jws_verify(const json_t *jws, EVP_PKEY *key)
{
    const json_t *array = NULL;
    const char *payl = NULL;

    if (!key)
        return false;

    if (json_unpack((json_t *) jws, "{s: s}", "payload", &payl) == -1)
        return false;

    array = json_object_get(jws, "signatures");
    if (json_is_array(array) && json_array_size(array) > 0) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *sig = json_array_get(array, i);

            if (do_verify(payl, sig, key))
                return true;
        }

        return false;
    }

    return do_verify(payl, jws, key);
}

bool __attribute__((warn_unused_result))
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
