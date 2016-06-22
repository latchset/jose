/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include "aeskw.h"
#include "rsaes.h"

#include <string.h>

static EVP_PKEY *
unseal_recip(EVP_PKEY *key, const json_t *prot, const json_t *shrd,
             const json_t *rcp)
{
    typeof(&aeskw_unseal) unsealer;
    const char *alg = NULL;
    EVP_PKEY *cek = NULL;
    uint8_t *ct = NULL;
    uint8_t *pt = NULL;
    json_t *ek = NULL;
    ssize_t pl = 0;
    size_t ctl = 0;

    if (json_unpack((json_t *) prot, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) shrd, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) rcp, "{s: {s: s}}",
                    "header", "alg", &alg) == -1)
        return NULL;

    switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
                        "A128KW", "A192KW", "A256KW", NULL)) {
    case 0: unsealer = rsaes_unseal; break;
    case 1: unsealer = rsaes_unseal; break;
    case 2: unsealer = rsaes_unseal; break;
    case 3: unsealer = aeskw_unseal; break;
    case 4: unsealer = aeskw_unseal; break;
    case 5: unsealer = aeskw_unseal; break;
    default: return NULL;
    }

    ek = json_object_get(rcp, "encrypted_key");
    if (!json_is_string(ek))
        return NULL;

    ctl = jose_b64_dlen(json_string_length(ek));
    ct = malloc(ctl);
    if (!ct)
        return NULL;

    if (!jose_b64_decode(json_string_value(ek), ct))
        goto egress;

    pt = malloc(ctl);
    if (!pt)
        goto egress;

    pl = unsealer(alg, key, ct, ctl, pt);
    if (pl >= 0)
        cek = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pt, pl);

egress:
    free(pt);
    free(ct);
    return cek;
}

EVP_PKEY *
jose_jwe_unseal(const json_t *jwe, EVP_PKEY *key)
{
    const json_t *prot = NULL;
    const json_t *shrd = NULL;
    const json_t *rcps = NULL;
    EVP_PKEY *cek = NULL;
    json_t *p = NULL;

    if (json_unpack((json_t *) jwe, "{s? o, s? o, s? o}",
                    "protected", &prot, "unprotected", &shrd,
                    "recipients", &rcps) == -1)
        return NULL;

    p = jose_b64_decode_json_load(prot);
    if (prot && !p)
        return NULL;

    if (json_is_array(rcps)) {
        for (size_t i = 0; i < json_array_size(rcps) && !cek; i++) {
            const json_t *recp = json_array_get(rcps, i);
            cek = unseal_recip(key, p, shrd, recp);
        }
    } else if (!rcps) {
        cek = unseal_recip(key, p, shrd, jwe);
    }

    json_decref(p);
    return cek;
}

EVP_PKEY *
jose_jwe_unseal_jwk(const json_t *jwe, const json_t *jwk)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY *cek = NULL;

    key = jose_jwk_to_key(jwk);
    if (!key)
        return NULL;

    cek = jose_jwe_unseal(jwe, key);
    EVP_PKEY_free(key);
    return cek;
}
