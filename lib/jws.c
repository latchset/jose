/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>

#include <string.h>

static jose_jws_signer_t *signers;

void
jose_jws_register_signer(jose_jws_signer_t *signer)
{
    signer->next = signers;
    signers = signer;
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

static const jose_jws_signer_t *
find(const char *alg)
{
    for (const jose_jws_signer_t *s = signers; s; s = s->next) {
        for (size_t i = 0; s->algs[i]; i++) {
            if (strcmp(alg, s->algs[i]) == 0)
                return s;
        }
    }

    return NULL;
}

bool
jose_jws_sign(json_t *jws, const json_t *jwk, json_t *sig)
{
    const jose_jws_signer_t *signer = NULL;
    const char *payl = NULL;
    const char *prot = NULL;
    const char *kalg = NULL;
    const char *alg = NULL;
    json_t *p = NULL;
    bool ret = false;

    if (!sig)
        sig = json_object();

    if (!jose_jwk_allowed(jwk, "sig", "sign"))
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
        for (signer = signers; signer && !alg; signer = signer->next)
            alg = signer->suggest(jwk);

        if (!set_protected_new(sig, "alg", json_string(alg)))
            goto egress;
    }

    if (kalg && strcmp(alg, kalg) != 0)
        goto egress;

    if (json_unpack(jws, "{s:s}", "payload", &payl) == -1)
        goto egress;

    prot = encode_protected(sig);
    if (!prot)
        goto egress;

    signer = find(alg);
    if (!signer)
        goto egress;

    if (signer->sign(sig, jwk, alg, prot, payl))
        ret = add_entity(jws, sig, "signatures", "signature", "protected",
                         "header", NULL);

egress:
    json_decref(sig);
    json_decref(p);
    return ret;
}

static bool
verify_sig(const char *payl, const json_t *sig, const json_t *jwk)
{
    const jose_jws_signer_t *signer = NULL;
    const char *prot = NULL;
    const char *sign = NULL;
    const char *kalg = NULL;
    const char *palg = NULL;
    const char *halg = NULL;
    json_t *p = NULL;
    bool ret = false;

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

    signer = find(palg ? palg : halg);
    if (!signer)
        goto egress;

    ret = signer->verify(sig, jwk, palg ? palg : halg, prot ? prot : "", payl);

egress:
    json_decref(p);
    return ret;
}

bool
jose_jws_verify(const json_t *jws, const json_t *jwk)
{
    const json_t *array = NULL;
    const char *payl = NULL;

    if (!jose_jwk_allowed(jwk, "sig", "verify"))
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

json_t *
jose_jws_merge_header(const json_t *sig)
{
    json_t *p = NULL;
    json_t *h = NULL;

    p = json_object_get(sig, "protected");
    if (!p)
        p = json_object();
    else if (json_is_object(p))
        p = json_deep_copy(p);
    else if (json_is_string(p))
        p = jose_b64_decode_json_load(p);

    if (!json_is_object(p)) {
        json_decref(p);
        return NULL;
    }

    h = json_object_get(sig, "header");
    if (h) {
        if (json_object_update_missing(p, h) == -1) {
            json_decref(p);
            return NULL;
        }
    }

    return p;
}
