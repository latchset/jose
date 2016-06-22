/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include "rsaes.h"
#include "aeskw.h"

#include <string.h>

static const char *
suggest(EVP_PKEY *key)
{
    size_t len = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        if (!EVP_PKEY_get0_hmac(key, &len))
            return NULL;

        switch (len * 8) {
        case 128: return "A128KW";
        case 192: return "A192KW";
        case 256: return "A256KW";
        default: return NULL;
        }

    case EVP_PKEY_RSA: return "RSA-OAEP";
    default: return NULL;
    }
}

static char *
choose_alg(json_t *jwe, EVP_PKEY *key, json_t *rcp, const char *kalg)
{
    const char *alg = NULL;
    json_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;

    if (json_unpack(jwe, "{s?O,s?o}", "protected", &p,
                    "unprotected", &s) == -1)
        return NULL;

    if (json_is_string(p)) {
        json_t *dec = jose_b64_decode_json_load(p);
        json_decref(p);
        p = dec;
    }

    if (p && !json_is_object(p))
        goto egress;

    if (json_unpack(p, "{s:s}", "alg", &alg) == 0)
        goto egress;

    if (json_unpack(s, "{s:s}", "alg", &alg) == 0)
        goto egress;

    if (json_unpack(rcp, "{s:{s:s}}", "header", "alg", &alg) == 0)
        goto egress;

    alg = kalg;
    if (!alg)
        alg = suggest(key);

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1) {
        alg = NULL;
        goto egress;
    }

    if (json_object_set_new(h, "alg", json_string(alg)) == -1)
        alg = NULL;

egress:
    if (alg) {
        if (!kalg || strcmp(kalg, alg) == 0)
            alg = strdup(alg);
        else
            alg = NULL;
    }
    json_decref(p);
    return (char *) alg;
}

static bool
jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp,
         const char *kalg)
{
    typeof(&aeskw_seal) sealer;
    const uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    json_t *tmp = NULL;
    char *alg = NULL;
    bool ret = false;
    size_t ptl = 0;
    size_t ctl = 0;

    if (!rcp)
        rcp = json_object();

    if (!json_is_object(rcp))
        goto egress;

    alg = choose_alg(jwe, key, rcp, kalg);
    if (!alg)
        goto egress;

    switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW", NULL)) {
    case 0: sealer = rsaes_seal; break;
    case 1: sealer = rsaes_seal; break;
    case 2: sealer = rsaes_seal; break;
    case 3: sealer = aeskw_seal; break;
    case 4: sealer = aeskw_seal; break;
    case 5: sealer = aeskw_seal; break;
    default: goto egress;
    }

    pt = EVP_PKEY_get0_hmac(cek, &ptl);
    if (!pt)
        goto egress;

    ct = sealer(alg, key, pt, ptl, &ctl);
    if (!ct)
        goto egress;

    tmp = jose_b64_encode_json(ct, ctl);
    if (json_object_set_new(rcp, "encrypted_key", tmp) == -1)
        goto egress;

    ret = add_entity(jwe, rcp, "recipients");

egress:
    json_decref(rcp);
    free(alg);
    free(ct);
    return ret;
}

bool
jose_jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp)
{
    return jwe_seal(jwe, cek, key, rcp, NULL);
}

bool
jose_jwe_seal_jwk(json_t *jwe, EVP_PKEY *cek, const json_t *jwk, json_t *rcp)
{
    const char *alg = NULL;
    EVP_PKEY *key = NULL;
    bool ret = false;

    if (!jose_jwk_use_allowed(jwk, "enc"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "wrapKey"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &alg) == -1)
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (key)
        ret = jwe_seal(jwe, cek, key, json_incref(rcp), alg);

egress:
    EVP_PKEY_free(key);
    json_decref(rcp);
    return ret;
}
