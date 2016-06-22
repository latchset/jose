/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jws.h"
#include "b64.h"
#include "jwk.h"
#include "conv.h"

#include "hmac.h"
#include "ecdsa.h"
#include "rsassa.h"

#include <string.h>

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

static char *
choose_alg(json_t *sig, EVP_PKEY *key, const char *kalg)
{
    const char *alg = NULL;
    json_t *enc = NULL;
    json_t *dec = NULL;

    if (json_unpack(sig, "{s:{s:s}}", "protected", "alg", &alg) == 0)
        goto egress;

    enc = json_object_get(sig, "protected");
    dec = jose_b64_decode_json_load(enc);
    if (json_is_string(enc) && !json_is_object(dec))
        goto egress;

    if (json_unpack(dec, "{s:s}", "alg", &alg) == 0)
        goto egress;

    if (json_unpack(sig, "{s:{s:s}}", "header", "alg", &alg) == 0)
        goto egress;

    alg = kalg;
    if (!alg) {
        switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_HMAC: alg = hmac_suggest(key); break;
        case EVP_PKEY_RSA: alg = rsassa_suggest(key); break;
        case EVP_PKEY_EC: alg = ecdsa_suggest(key); break;
        }
    }
    if (!alg)
        goto egress;

    if (!dec)
        dec = json_object();

    if (json_object_set_new(dec, "alg", json_string(alg)) == -1 ||
        json_object_set_new(sig, "protected",
                            jose_b64_encode_json_dump(dec)) == -1)
        alg = NULL;

egress:
    if (alg) {
        if (!kalg || strcmp(kalg, alg) == 0)
            alg = strdup(alg);
        else
            alg = NULL;
    }
    json_decref(dec);
    return (char *) alg;
}

static bool
jws_sign(json_t *jws, EVP_PKEY *key, json_t *sig, const char *kalg)
{
    const char *payl = NULL;
    const char *prot = NULL;
    uint8_t *s = NULL;
    json_t *p = NULL;
    char *alg = NULL;
    bool ret = false;
    size_t len = 0;

    if (!key)
        goto egress;

    if (json_unpack(jws, "{s:s}", "payload", &payl) == -1)
        goto egress;

    if (!json_is_object(sig)) {
        json_decref(sig);
        sig = json_object();
    }

    alg = choose_alg(sig, key, kalg);
    if (!alg)
        goto egress;

    p = encode_protected(sig);
    if (!p)
        goto egress;
    prot = json_string_value(p);

    switch (alg[0]) {
    case 'H': s = hmac_sign(alg, key, prot, payl, &len); break;
    case 'R': s = rsassa_sign(alg, key, prot, payl, &len); break;
    case 'P': s = rsassa_sign(alg, key, prot, payl, &len); break;
    case 'E': s = ecdsa_sign(alg, key, prot, payl, &len); break;
    }

    if (s) {
        json_t *tmp = jose_b64_encode_json(s, len);
        if (json_object_set_new(sig, "signature", tmp) == -1)
            goto egress;

        ret = add_entity(jws, sig, "signatures");
    }

egress:
    json_decref(sig);
    free(alg);
    free(s);
    return ret;
}

bool
jose_jws_sign(json_t *jws, EVP_PKEY *key, json_t *sig)
{
    return jws_sign(jws, key, sig, NULL);
}

bool
jose_jws_sign_jwk(json_t *jws, const json_t *jwk, json_t *sig)
{
    const char *kalg = NULL;
    EVP_PKEY *key = NULL;
    bool ret = false;

    if (!jose_jwk_use_allowed(jwk, "sig"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "sign"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (!key)
        goto egress;

    ret = jws_sign(jws, key, json_incref(sig), kalg);
    EVP_PKEY_free(key);

egress:
    json_decref(sig);
    return ret;
}

static bool
verify_sig(const char *payl, const json_t *sig, EVP_PKEY *key)
{
    const char *prot = NULL;
    const char *sign = NULL;
    const char *alg = NULL;
    uint8_t *buf = NULL;
    json_t *p = NULL;
    json_t *h = NULL;
    bool ret = false;
    size_t len = 0;

    if (json_unpack((json_t *) sig, "{s: s, s? o, s? o}", "signature", &sign,
                    "protected", &p, "header", &h) == -1)
        return false;

    if (!p && !h)
        return false;

    if (p) {
        prot = json_string_value(p);
        p = jose_b64_decode_json_load(p);
        if (!p)
            goto egress;
    }

    if (json_unpack(p, "{s: s}", "alg", &alg) == -1 &&
        json_unpack(h, "{s: s}", "alg", &alg) == -1)
        goto egress;

    len = jose_b64_dlen(strlen(sign));
    buf = malloc(len);
    if (!buf)
        goto egress;

    if (!jose_b64_decode(sign, buf))
        goto egress;

    switch (alg[0]) {
    case 'E': ret = ecdsa_verify(alg, key, prot, payl, buf, len); break;
    case 'H': ret = hmac_verify(alg, key, prot, payl, buf, len); break;
    case 'P': ret = rsassa_verify(alg, key, prot, payl, buf, len); break;
    case 'R': ret = rsassa_verify(alg, key, prot, payl, buf, len); break;
    }

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
jose_jws_verify_jwk(const json_t *jws, const json_t *jwk)
{
    EVP_PKEY *key = NULL;
    bool valid = false;

    if (!jose_jwk_use_allowed(jwk, "sig"))
        return false;

    if (!jose_jwk_op_allowed(jwk, "verify"))
        return false;

    key = jose_jwk_to_key(jwk);
    valid = jose_jws_verify(jws, key);
    EVP_PKEY_free(key);
    return valid;
}
