/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jws.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include <openssl/ecdsa.h>
#include <openssl/hmac.h>

#include <string.h>

static jose_jws_alg_t *algs;

void
jose_jws_alg_register(jose_jws_alg_t *alg)
{
    jose_jws_alg_t **a = &algs;

    while (*a && (*a)->priority < alg->priority)
        a = &(*a)->next;

    alg->next = *a;
    *a = alg;

    for (jose_jws_alg_t *b = algs; b; b = b->next) {
        for (size_t i = 0; b->algorithms[i]; i++)
            fprintf(stderr, "%u %s\n", b->priority, b->algorithms[i]);
    }
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

static bool
add_sig(json_t *jws, json_t *head, const char *data, const buf_t *sig)
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

    if (json_object_set_new(jws, "signature",
                            jose_b64_encode(sig->buf, sig->len)) < 0)
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
              const EVP_PKEY *key, jose_jws_flags_t flags)
{
    const char *alg = NULL;
    buf_t *sig = NULL;
    json_t *h = NULL;
    json_t *p = NULL;
    bool ret = false;
    char *d = NULL;

    if (!key)
        return false;

    h = json_deep_copy(head);
    if (head && !h)
        goto egress;

    p = json_deep_copy(prot);
    if (prot && !p)
        goto egress;

    /* Look up the algorithm, or try to detect it. */
    if (json_unpack((json_t *) prot, "{s:s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) head, "{s:s}", "alg", &alg) == -1) {
        for (jose_jws_alg_t *a = algs; a && !alg; a = a->next) {
            if (!a->suggest)
                continue;

            alg = a->suggest(key);
        }

        if (!alg)
            goto egress;

        if (flags & JOSE_JWS_FLAGS_ALG_HEAD) {
            if (!h)
                h = json_object();

            if (json_object_set_new(h, "alg", json_string(alg)) == -1)
                goto egress;
        }

        if (flags & JOSE_JWS_FLAGS_ALG_PROT) {
            if (!p)
                p = json_object();

            if (json_object_set_new(p, "alg", json_string(alg)) == -1)
                goto egress;
        }
    }

    d = make_data(jws, p);
    if (!d)
        goto egress;

    for (jose_jws_alg_t *a = algs; a && !sig; a = a->next) {
        if (!a->sign)
            continue;

        sig = a->sign(key, alg, d);
    }

    if (sig)
        ret = add_sig(jws, h, d, sig);

egress:
    buf_free(sig);
    json_decref(h);
    json_decref(p);
    free(d);
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
    ret = jose_jws_sign(jws, h, p, key, flags);

egress:
    EVP_PKEY_free(key);
    json_decref(h);
    json_decref(p);
    return ret;
}

static bool
verify(const json_t *pay, const json_t *sig, const EVP_PKEY *key)
{
    const json_t *signature = NULL;
    const json_t *protected = NULL;
    const json_t *header = NULL;
    const json_t *alg = NULL;
    json_t *prot = NULL;
    buf_t *buf = NULL;
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

    if (!json_is_string(signature))
        return false;

    buf = buf_new(jose_b64_dlen(json_string_length(signature)), false);
    if (!buf)
        return false;

    if (!jose_b64_decode(signature, buf->buf))
        goto egress;

    prot = jose_b64_decode_json(protected);
    if (protected && !prot)
        goto egress;

    alg = json_object_get(prot, "alg");
    if (!json_is_string(alg))
        alg = json_object_get(header, "alg");
    if (alg && !json_is_string(alg))
        goto egress;

    asprintf(&data, "%s.%s", protected ? json_string_value(protected) : "",
             json_string_value(pay));
    if (!data)
        goto egress;

    for (jose_jws_alg_t *a = algs; a && !ret; a = a->next) {
        if (!a->verify)
            continue;

        ret = a->verify(key, json_string_value(alg), data, buf->buf, buf->len);
    }

egress:
    buf_free(buf);
    json_decref(prot);
    free(data);
    return ret;
}

bool __attribute__((warn_unused_result))
jose_jws_verify(const json_t *jws, const EVP_PKEY *key)
{
    const json_t *array = NULL;

    if (!jws)
        return false;

    if (!key)
        return false;

    array = json_object_get(jws, "signatures");
    if (json_is_array(array) && json_array_size(array) > 0) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *sig = json_array_get(array, i);

            if (verify(json_object_get(jws, "payload"), sig, key))
                return true;
        }

        return false;
    }

    return verify(json_object_get(jws, "payload"), jws, key);
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
