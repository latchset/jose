/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jose.h"
#include "conv.h"

#include <openssl/ecdsa.h>
#include <openssl/hmac.h>

#include <string.h>

json_t *
jose_jws_from_compact(const char *jws)
{
    size_t len[3] = { 0, 0, 0 };
    json_t *out = NULL;
    size_t c = 0;

    if (!jws)
        return NULL;

    for (size_t i = 0; jws[i]; i++) {
        if (jws[i] != '.')
            len[c]++;
        else if (++c > 2)
            return NULL;
    }

    if (c != 2 || len[0] == 0 || len[1] == 0)
        return NULL;

    out = json_pack("{s: s%}", "payload", &jws[len[0] + 1], len[1]);
    if (!out)
        return NULL;

    if (json_object_set_new(out, "protected", json_stringn(jws, len[0])) < 0)
        goto error;

    if (len[2] > 0) {
        json_t *tmp = NULL;

        tmp = json_stringn(&jws[len[0] + len[1] + 2], len[2]);
        if (json_object_set_new(out, "signature", tmp) == -1)
            goto error;
    }

    return out;

error:
    json_decref(out);
    return NULL;
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

static size_t
str_match(const char *str, ...)
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

static bool
add_sig(json_t *jws, json_t *head, const char *data,
        const uint8_t sig[], size_t len)
{
    json_t *signatures = NULL;
    json_t *signature = NULL;
    json_t *protected = NULL;
    json_t *header = NULL;
    const char *d = NULL;

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

    d = strchr(data, '.');
    if (!d)
        return false;

    if (json_object_set_new(jws, "signature", jose_b64_encode(sig, len)) < 0)
        return false;

    if (d > data) {
        json_t *tmp = json_stringn(data, d - data);
        if (json_object_set_new(jws, "protected", tmp) < 0)
            return false;
    }

    if (json_object_size(head) > 0) {
        if (json_object_set(jws, "header", head) < 0)
            return false;
    } else if (d == data)
        return false;

    return true;
}

static bool
sign_HMAC(json_t *jws, json_t *head, const char *data,
          const json_t *jwk, const char *alg)
{
    const EVP_MD *md = NULL;
    jose_key_t *key = NULL;
    bool ret = false;

    switch (str_match(alg, "HS256", "HS384", "HS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t sig[EVP_MD_size(md)];

    key = jose_jwk_to_key(jwk);
    if (!key)
        return false;

    if (sizeof(sig) > key->len)
        goto egress;

    if (!HMAC(md, key->key, key->len, (uint8_t *) data,
              strlen(data), sig, NULL))
        goto egress;

    ret = add_sig(jws, head, data, sig, sizeof(sig));

egress:
    jose_key_free(key);
    return ret;
}

static bool
sign_RSA(json_t *jws, json_t *head, const char *data,
         const json_t *jwk, const char *alg)
{
    const EVP_MD *md = NULL;
    bool ret = false;
    RSA *key = NULL;

    switch (str_match(alg, "RS256", "RS384", "RS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t dgst[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), dgst, NULL, md, NULL) < 0)
        return false;

    key = jose_jwk_to_rsa(jwk);
    if (!key)
        return false;

    uint8_t sig[RSA_size(key)];
    unsigned int len = 0;

    /* Don't use small keys. RFC 7518 3.3 */
    if (sizeof(sig) < 2048 / 8)
        goto egress;

    if (!RSA_sign(EVP_MD_type(md), dgst, sizeof(dgst), sig, &len, key))
        goto egress;

    ret = add_sig(jws, head, data, sig, sizeof(sig));

egress:
    RSA_free(key);
    return ret;
}

static bool
sign_ECDSA(json_t *jws, json_t *head, const char *data,
           const json_t *jwk, const char *alg)
{
    const EVP_MD *md = NULL;
    ECDSA_SIG *ecdsa = NULL;
    EC_KEY *key = NULL;
    bool ret = false;

    switch (str_match(alg, "ES256", "ES384", "ES512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hsh[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
        return false;

    key = jose_jwk_to_ec(jwk);
    if (!key)
        return false;

    uint8_t sig[(EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8 * 2];

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key))) {
    case NID_X9_62_prime256v1:
        if (EVP_MD_type(md) != NID_sha256)
            goto egress;
        break;

    case NID_secp384r1:
        if (EVP_MD_type(md) != NID_sha384)
            goto egress;
        break;

    case NID_secp521r1:
        if (EVP_MD_type(md) != NID_sha512)
            goto egress;
        break;

    default:
        goto egress;
    }

    ecdsa = ECDSA_do_sign(hsh, sizeof(hsh), key);
    if (!ecdsa)
        goto egress;

    if (!bn_to_buf(ecdsa->r, sig, sizeof(sig) / 2))
        goto egress;

    if (!bn_to_buf(ecdsa->s, &sig[sizeof(sig) / 2], sizeof(sig) / 2))
        goto egress;

    ret = add_sig(jws, head, data, sig, sizeof(sig));

egress:
    ECDSA_SIG_free(ecdsa);
    EC_KEY_free(key);
    return ret;
}

static const char *
pick_size(size_t size, ...)
{
    va_list ap;

    va_start(ap, size);
    for (size_t min = va_arg(ap, size_t); min > 0; min = va_arg(ap, size_t)) {
        if (size >= min)
            return va_arg(ap, const char *);
    }

    return NULL;
}

static const char *
pick_alg(const json_t *jwk)
{
    const char *kty = NULL;
    const char *crv = NULL;
    const char *k = NULL;
    RSA *rsa = NULL;
    int bits = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s?s,s?s}",
                    "kty", &kty, "crv", &crv, "k", &k) == -1)
        return NULL;

    switch (str_match(kty, "oct", "RSA", "EC", NULL)) {
    case 0:
        if (!k)
            return NULL;

        return pick_size(jose_b64_dlen(strlen(k)),
                         64, "HS512", 48, "HS384", 32, "HS256", 0);

    case 1:
        rsa = jose_jwk_to_rsa(jwk);
        if (!rsa)
            return NULL;

        bits = RSA_size(rsa) * 8;
        RSA_free(rsa);

        return pick_size(bits, 4096, "RS512", 3072, "RS384", 2048, "RS256", 0);

    case 2:
        if (!crv)
            return NULL;

        switch (str_match(crv, "P-256", "P-384", "P-521", NULL)) {
        case 0: return "ES256";
        case 1: return "ES384";
        case 2: return "ES512";
        }

        return NULL;

    default:
        return NULL;
    }
}

static char *
make_data(json_t *jws, const json_t *prot)
{
    const char *payload = NULL;
    char *data = NULL;
    json_t *p = NULL;

    if (json_unpack(jws, "{s: s}", "payload", &payload) == -1)
        return NULL;

    if (json_is_object(prot) && json_object_size(prot) > 0)
        p = jose_b64_encode_json(prot);
    else
        p = json_string("");

    if (json_is_string(p))
        asprintf(&data, "%s.%s", json_string_value(p), payload);

    json_decref(p);
    return data;
}

bool
jose_jws_sign(json_t *jws, const json_t *head, const json_t *prot,
              const json_t *jwks, enum jose_jws_flags flags)
{
    const json_t *array = NULL;
    const char *alg = NULL;
    char *data = NULL;
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

            if (!jose_jws_sign(jws, head, prot, jwk, flags))
                return false;
        }

        return json_array_size(array) > 0;
    }

    h = json_deep_copy(head);
    if (head && !h)
        goto egress;

    if (!h && (flags & JOSE_JWS_FLAGS_HEAD)) {
        h = json_object();
        if (!json_is_object(h))
            goto egress;
    }

    p = json_deep_copy(prot);
    if (prot && !p)
        goto egress;

    if (!p && (flags & JOSE_JWS_FLAGS_PROT)) {
        p = json_object();
        if (!json_is_object(p))
            goto egress;
    }

    if (json_unpack(p, "{s: s}", "alg", &alg) == -1 &&
        json_unpack(h, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) jwks, "{s: s}", "alg", &alg) == -1 &&
        !(alg = pick_alg(jwks)))
        goto egress;

    if (flags & JOSE_JWS_FLAGS_ALG_HEAD && !json_object_get(h, "alg")) {
        if (json_object_set_new(h, "alg", json_string(alg)) == -1)
            goto egress;
    }

    if (flags & JOSE_JWS_FLAGS_ALG_PROT && !json_object_get(p, "alg")) {
        if (json_object_set_new(p, "alg", json_string(alg)) == -1)
            goto egress;
    }

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

    data = make_data(jws, p);
    if (!data)
        goto egress;

    switch (str_match(alg, "HS256", "HS384", "HS512", "RS256", "RS384",
                      "RS512", "ES256", "ES384", "ES512", NULL)) {
    case 0: ret = sign_HMAC(jws, h, data, jwks, alg); break;
    case 1: ret = sign_HMAC(jws, h, data, jwks, alg); break;
    case 2: ret = sign_HMAC(jws, h, data, jwks, alg); break;
    case 3: ret = sign_RSA(jws, h, data, jwks, alg); break;
    case 4: ret = sign_RSA(jws, h, data, jwks, alg); break;
    case 5: ret = sign_RSA(jws, h, data, jwks, alg); break;
    case 6: ret = sign_ECDSA(jws, h, data, jwks, alg); break;
    case 7: ret = sign_ECDSA(jws, h, data, jwks, alg); break;
    case 8: ret = sign_ECDSA(jws, h, data, jwks, alg); break;
    default: break;
    }

    free(data);

egress:
    json_decref(h);
    json_decref(p);
    return ret;
}

static bool
verify_HMAC(const json_t *jwk, const char *data, const jose_key_t *sig,
            const char *alg)
{
    const EVP_MD *md = NULL;
    jose_key_t *key = NULL;

    switch (str_match(alg, "HS256", "HS384", "HS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hmac[EVP_MD_size(md)];

    key = jose_jwk_to_key(jwk);
    if (!key)
        return false;

    if (!HMAC(md, key->key, key->len, (uint8_t *) data,
              strlen(data), hmac, NULL)) {
        jose_key_free(key);
        return false;
    }
    jose_key_free(key);

    return sizeof(hmac) == sig->len && memcmp(hmac, sig->key, sig->len) == 0;
}

static bool
verify_RSA(const json_t *jwk, const char *data, const jose_key_t *sig,
             const char *alg)
{
    const EVP_MD *md = NULL;
    bool ret = false;
    RSA *key = NULL;

    switch (str_match(alg, "RS256", "RS384", "RS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hsh[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
        return false;

    key = jose_jwk_to_rsa(jwk);
    if (!key)
        return false;

    ret = RSA_verify(EVP_MD_type(md), hsh, sizeof(hsh),
                     sig->key, sig->len, key) == 1;
    RSA_free(key);
    return ret;
}

static bool
verify_ECDSA(const json_t *jwk, const char *data, const jose_key_t *sig,
             const char *alg)
{
    const EVP_MD *md = NULL;
    ECDSA_SIG ecdsa = {};
    EC_KEY *key = NULL;
    bool ret = false;

    switch (str_match(alg, "ES256", "ES384", "ES512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hsh[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
        return false;

    ecdsa.r = bn_from_buf(sig->key, sig->len / 2);
    ecdsa.s = bn_from_buf(&sig->key[sig->len / 2], sig->len / 2);
    if (ecdsa.r && ecdsa.s) {
        key = jose_jwk_to_ec(jwk);
        if (key)
            ret = ECDSA_do_verify(hsh, sizeof(hsh), &ecdsa, key) == 1;
    }

    EC_KEY_free(key);
    BN_free(ecdsa.r);
    BN_free(ecdsa.s);
    return ret;
}

static bool
verify(const json_t *sig, const json_t *pay, const json_t *jwk)
{
    const json_t *signature = NULL;
    const json_t *protected = NULL;
    const json_t *header = NULL;
    const json_t *alg = NULL;
    jose_key_t *buf = NULL;
    json_t *prot = NULL;
    json_t *head = NULL;
    char *data = NULL;
    bool ret = false;

    if (!json_is_string(pay))
        return false;

    if (json_unpack((json_t *) sig, "{s: o, s? o, s? o}",
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1)
        return false;

    if (!protected && !header)
        return false;

    buf = jose_b64_decode_key(signature);
    if (!buf)
        return false;

    prot = jose_b64_decode_json(protected);
    head = jose_b64_decode_json(header);
    if (!prot && !head)
        goto egress;

    alg = json_object_get(prot, "alg");
    if (!json_is_string(alg))
        alg = json_object_get(head, "alg");
    if (!json_is_string(alg))
        goto egress;

    asprintf(&data, "%s.%s", protected ? json_string_value(protected) : "",
             json_string_value(pay));
    if (!data)
        goto egress;

    switch (str_match(json_string_value(alg),
                      "HS256", "HS384", "HS512",
                      "RS256", "RS384", "RS512",
                      "ES256", "ES384", "ES512", NULL)) {
    case 0: ret = verify_HMAC(jwk, data, buf, json_string_value(alg)); break;
    case 1: ret = verify_HMAC(jwk, data, buf, json_string_value(alg)); break;
    case 2: ret = verify_HMAC(jwk, data, buf, json_string_value(alg)); break;
    case 3: ret = verify_RSA(jwk, data, buf, json_string_value(alg)); break;
    case 4: ret = verify_RSA(jwk, data, buf, json_string_value(alg)); break;
    case 5: ret = verify_RSA(jwk, data, buf, json_string_value(alg)); break;
    case 6: ret = verify_ECDSA(jwk, data, buf, json_string_value(alg)); break;
    case 7: ret = verify_ECDSA(jwk, data, buf, json_string_value(alg)); break;
    case 8: ret = verify_ECDSA(jwk, data, buf, json_string_value(alg)); break;
    }

egress:
    jose_key_free(buf);
    json_decref(prot);
    json_decref(head);
    free(data);
    return ret;
}

bool
jose_jws_verify(const json_t *jws, const json_t *jwks, bool all)
{
    const json_t *array = NULL;

    if (!jws || !jwks)
        return false;

    if (json_is_array(jwks))
        array = jwks;
    else if (json_is_array(json_object_get(jwks, "keys")))
        array = json_object_get(jwks, "keys");

    if (json_is_array(array)) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *jwk = json_array_get(array, i);
            bool valid = false;

            valid = jose_jws_verify(jws, jwk, all);
            if (valid && !all)
                return true;
            if (!valid && all)
                return false;
        }

        return all && json_array_size(array) > 0;
    }

    array = json_object_get(jws, "signatures");
    if (json_is_array(array) && json_array_size(array) > 0) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *sig = json_array_get(array, i);

            if (verify(sig, json_object_get(jws, "payload"), jwks))
                return true;
        }

        return false;
    }

    return verify(jws, json_object_get(jws, "payload"), jwks);
}



































