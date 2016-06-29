/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jws.h"
#include "b64.h"
#include "jwk.h"
#include "hook.h"
#include "conv.h"

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

bool
jose_jws_sign(json_t *jws, const json_t *jwk, json_t *sig)
{
    const char *payl = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *alg = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *sg = NULL;
    json_t *p = NULL;
    bool ret = false;
    size_t sgl = 0;

    if (!sig)
        sig = json_object();

    if (!jose_jwk_use_allowed(jwk, "sig"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "sign"))
        goto egress;

    if (json_unpack(sig, "{s?o}", "protected", &p) == -1)
        goto egress;

    if (json_is_object(p))
        p = json_incref(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);
    else if (p)
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    if (json_unpack(p, "{s:s}", "alg", &alg) == -1 &&
        json_unpack(sig, "{s:{s:s}}", "header", "alg", &alg) == -1) {
        alg = kalg;
        for (const algo_t *a = algos; a && !alg; a = a->next) {
            if (a->type == ALGO_TYPE_SIGN && a->suggest)
                alg = a->suggest(jwk);
        }
        if (!set_protected_new(sig, "alg", json_string(alg)))
            goto egress;
    }

    if (kalg && strcmp(alg, kalg) != 0)
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (!key)
        goto egress;

    if (json_unpack(jws, "{s:s}", "payload", &payl) == -1)
        goto egress;

    prot = encode_protected(sig);
    if (!prot)
        goto egress;

    for (const algo_t *a = algos; a && !sg; a = a->next) {
        if (a->type != ALGO_TYPE_SIGN || !a->sign)
            continue;

        for (size_t i = 0; a->names[i] && !sg; i++) {
            if (strcmp(alg, a->names[i]) != 0)
                continue;

            sg = a->sign(alg, key, prot, payl, &sgl);
        }
    }

    if (sg) {
        if (json_object_set_new(sig, "signature",
                                jose_b64_encode_json(sg, sgl)) == -1)
            goto egress;

        ret = add_entity(jws, sig, "signatures", "signature", "protected",
                         "header", NULL);
    }

egress:
    EVP_PKEY_free(key);
    json_decref(sig);
    json_decref(p);
    free(sg);
    return ret;
}

static bool
verify_sig(const char *payl, const json_t *sig, const json_t *jwk)
{
    const char *prot = NULL;
    const char *sign = NULL;
    const char *kalg = NULL;
    const char *palg = NULL;
    const char *halg = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *sg = NULL;
    json_t *p = NULL;
    bool ret = false;
    size_t sgl = 0;

    if (json_unpack((json_t *) sig, "{s:s,s?o,s?s,s?{s?s}}",
                    "signature", &sign, "protected", &p, "protected", &prot,
                    "header", "alg", &halg) == -1)
        return false;

    if (p) {
        if (!json_is_string(p))
            return false;

        p = jose_b64_decode_json_load(p);
        if (json_unpack(p, "{s:s}", "alg", &palg) == -1)
            goto egress;
    }

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    if (palg && halg)
        goto egress;

    if (!palg && !halg) {
        if (!kalg)
            goto egress;
        halg = kalg;
    }

    if (kalg && strcmp(palg ? palg : halg, kalg) != 0)
        goto egress;

    sgl = jose_b64_dlen(strlen(sign));
    sg = malloc(sgl);
    if (!sg)
        goto egress;

    if (!jose_b64_decode(sign, sg))
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (!key)
        goto egress;

    for (const algo_t *a = algos; a; a = a->next) {
        if (a->type != ALGO_TYPE_SIGN || !a->verify)
            continue;

        for (size_t i = 0; a->names[i]; i++) {
            if (strcmp(palg ? palg : halg, a->names[i]) != 0)
                continue;

            ret = a->verify(palg ? palg : halg, key,
                            prot ? prot : "",
                            payl ? payl : "", sg, sgl);
            goto egress;
        }
    }

egress:
    EVP_PKEY_free(key);
    json_decref(p);
    free(sg);
    return ret;
}

bool
jose_jws_verify(const json_t *jws, const json_t *jwk)
{
    const json_t *array = NULL;
    const char *payl = NULL;

    if (!jose_jwk_use_allowed(jwk, "sig"))
        return false;

    if (!jose_jwk_op_allowed(jwk, "verify"))
        return false;

    if (json_unpack((json_t *) jws, "{s: s}", "payload", &payl) == -1)
        return false;

    /* Verify signatures in general format. */
    array = json_object_get(jws, "signatures");
    if (json_is_array(array) && json_array_size(array) > 0) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            if (verify_sig(payl, json_array_get(array, i), jwk))
                return true;
        }

        return false;
    }

    /* Verify the signature in flattened format. */
    return verify_sig(payl, jws, jwk);
}
