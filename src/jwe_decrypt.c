/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include "aescbch.h"
#include "aesgcm.h"

#include <string.h>

static uint8_t *
decode(const char *enc, size_t *l)
{
    uint8_t *dec = NULL;

    *l = jose_b64_dlen(strlen(enc));

    dec = malloc(*l);
    if (!dec)
        return NULL;

    if (jose_b64_decode(enc, dec))
        return dec;

    free(dec);
    return NULL;
}

ssize_t
jose_jwe_decrypt(const json_t *jwe, EVP_PKEY *cek, uint8_t pt[])
{
    typeof(&aesgcm_decrypt) decryptor;
    const json_t *prot = NULL;
    const json_t *shrd = NULL;
    const char *etg = NULL;
    const char *eiv = NULL;
    const char *ect = NULL;
    const char *aad = NULL;
    const char *enc = NULL;
    uint8_t *tg = NULL;
    uint8_t *ct = NULL;
    uint8_t *iv = NULL;
    json_t *p = NULL;
    ssize_t ptl = -1;
    size_t tgl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (json_unpack((json_t *) jwe, "{s?o, s?o, s?s, s:s, s:s, s:s}",
                    "unprotected", &shrd, "protected", &prot, "aad", &aad,
                    "ciphertext", &ect, "tag", &etg, "iv", &eiv) == -1)
        return -1;

    p = jose_b64_decode_json_load(prot);
    if (prot && !p)
        goto egress;

    if (json_unpack(p, "{s: s}", "enc", &enc) == -1 &&
        json_unpack((json_t *) shrd, "{s: s}", "enc", &enc) == -1)
        goto egress;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: decryptor = aesgcm_decrypt; break;
    case 1: decryptor = aesgcm_decrypt; break;
    case 2: decryptor = aesgcm_decrypt; break;
    case 3: decryptor = aescbch_decrypt; break;
    case 4: decryptor = aescbch_decrypt; break;
    case 5: decryptor = aescbch_decrypt; break;
    default: goto egress;
    }

    iv = decode(eiv, &ivl);
    ct = decode(ect, &ctl);
    tg = decode(etg, &tgl);
    if (iv && ct && tg) {
        ptl = decryptor(enc, cek, iv, ivl, ct, ctl, tg, tgl, pt,
                        json_string_value(prot),
                        aad ? "." : NULL, aad ? aad : "", NULL);
    }

egress:
    json_decref(p);
    free(tg);
    free(ct);
    free(iv);
    return ptl;
}

json_t *
jose_jwe_decrypt_json(const json_t *jwe, EVP_PKEY *cek)
{
    json_t *json = NULL;
    uint8_t *pt = NULL;
    json_t *ct = NULL;
    ssize_t ptl = -1;

    ct = json_object_get(jwe, "ciphertext");
    if (!json_is_string(ct))
        return NULL;

    pt = malloc(jose_b64_dlen(json_string_length(ct)));
    if (pt) {
        ptl = jose_jwe_decrypt(jwe, cek, pt);
        if (ptl >= 0)
            json = json_loadb((char *) pt, ptl, JSON_DECODE_ANY, NULL);
        free(pt);
    }

    return json;
}
