/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include "aescbch.h"
#include "aesgcm.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <string.h>

static char *
choose_enc(json_t *jwe, EVP_PKEY *cek)
{
    const char *enc = NULL;
    json_t *p = NULL;
    json_t *s = NULL;
    size_t len = 0;

    if (!cek)
        return NULL;

    if (EVP_PKEY_base_id(cek) != EVP_PKEY_HMAC)
        return NULL;

    if (!EVP_PKEY_get0_hmac(cek, &len))
        return NULL;

    if (json_unpack(jwe, "{s?O,s?o}", "protected", &p,
                    "unprotected", &s) == -1)
        return NULL;

    if (json_is_string(p)) {
        json_t *dec = jose_b64_decode_json_load(p);
        json_decref(p);
        p = dec;
    }

    if (p && !json_is_object(p))
        goto error;

    if (json_unpack(p, "{s:s}", "enc", &enc) == -1 &&
        json_unpack(s, "{s:s}", "enc", &enc) == -1) {
        switch (len) {
        case 16: enc = "A128GCM"; break;
        case 24: enc = "A192GCM"; break;
        case 32: enc = "A128CBC-HS256"; break;
        case 48: enc = "A192CBC-HS384"; break;
        case 64: enc = "A256CBC-HS512"; break;
        default: goto error;
        }

        if (!p)
            p = json_object();

        if (json_object_set_new(p, "enc", json_string(enc)) == -1 ||
            json_object_set(jwe, "protected", p) == -1)
            goto error;
    }

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: if (len != 16) goto error; break;
    case 1: if (len != 24) goto error; break;
    case 2: if (len != 32) goto error; break;
    case 3: if (len != 32) goto error; break;
    case 4: if (len != 48) goto error; break;
    case 5: if (len != 64) goto error; break;
    default: goto error;
    }

    enc = strdup(enc);
    json_decref(p);
    return (char *) enc;

error:
    json_decref(p);
    return NULL;
}

bool
jose_jwe_encrypt(json_t *jwe, EVP_PKEY *cek, const uint8_t pt[], size_t ptl)
{
    typeof(&aesgcm_encrypt) encryptor;
    uint8_t *ivcttag = NULL;
    const char *aad = NULL;
    json_t *tmp = NULL;
    json_t *p = NULL;
    bool ret = false;
    char *enc = NULL;
    size_t tgl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (json_unpack(jwe, "{s?s}", "aad", &aad) == -1)
        goto egress;

    enc = choose_enc(jwe, cek);
    if (!enc)
        goto egress;

    p = encode_protected(jwe);
    if (!p)
        goto egress;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "Ai192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: encryptor = aesgcm_encrypt; break;
    case 1: encryptor = aesgcm_encrypt; break;
    case 2: encryptor = aesgcm_encrypt; break;
    case 3: encryptor = aescbch_encrypt; break;
    case 4: encryptor = aescbch_encrypt; break;
    case 5: encryptor = aescbch_encrypt; break;
    default: goto egress;
    }

    ivcttag = encryptor(enc, cek, pt, ptl, &ivl, &ctl, &tgl,
                        json_string_value(p), aad ? "." : NULL,
                        aad ? aad : "", NULL);
    if (!ivcttag)
        goto egress;

    if (ivl > 0) {
        tmp = jose_b64_encode_json(ivcttag, ivl);
        if (json_object_set_new(jwe, "iv", tmp) == -1)
            goto egress;
    }

    tmp = jose_b64_encode_json(&ivcttag[ivl], ctl);
    if (json_object_set_new(jwe, "ciphertext", tmp) == -1)
        goto egress;

    if (tgl > 0) {
        tmp = jose_b64_encode_json(&ivcttag[ivl + ctl], tgl);
        if (json_object_set_new(jwe, "tag", tmp) == -1)
            goto egress;
    }

    ret = true;

egress:
    free(ivcttag);
    free(enc);
    return ret;
}

bool
jose_jwe_encrypt_json(json_t *jwe, EVP_PKEY *cek, const json_t *pt)
{
    char *ept = NULL;
    bool ret = false;

    ept = json_dumps(pt, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
    if (!ept)
        return NULL;

    ret = jose_jwe_encrypt(jwe, cek, (uint8_t *) ept, strlen(ept));
    free(ept);
    return ret;
}
