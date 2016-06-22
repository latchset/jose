/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <string.h>

static uint8_t *
encrypt(const char *enc, const char aad[], const uint8_t pt[], size_t ptl,
        EVP_PKEY *cek, size_t *ivl, size_t *ctl, size_t *tagl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *key = NULL;
    const EVP_MD *md = NULL;
    uint8_t *ivcttag = NULL;
    size_t ksz = 0;
    int len;

    key = EVP_PKEY_get0_hmac(cek, &ksz);
    if (!key)
        return NULL;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512", NULL)) {
    case 0: cph = EVP_aes_128_gcm(); *tagl = 16; break;
    case 1: cph = EVP_aes_192_gcm(); *tagl = 16; break;
    case 2: cph = EVP_aes_256_gcm(); *tagl = 16; break;
    case 3: cph = EVP_aes_128_cbc(); md = EVP_sha256(); *tagl = 16; break;
    case 4: cph = EVP_aes_192_cbc(); md = EVP_sha384(); *tagl = 24; break;
    case 5: cph = EVP_aes_256_cbc(); md = EVP_sha512(); *tagl = 32; break;
    default: return NULL;
    }

    if ((int) ksz != EVP_CIPHER_key_length(cph) * (md ? 2 : 1))
        return NULL;

    *ivl = EVP_CIPHER_iv_length(cph);
    ivcttag = malloc(*ivl + *tagl + ptl + EVP_CIPHER_block_size(cph) - 1);
    if (!ivcttag)
        return NULL;

    if (RAND_bytes(ivcttag, *ivl) <= 0)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (!md) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, *ivl, NULL) <= 0)
            goto error;
    }

    if (EVP_EncryptInit(ctx, NULL, md ? &key[ksz / 2] : key, ivcttag) <= 0)
        goto error;

    if (!md) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, (uint8_t *) aad,
                              strlen(aad)) <= 0)
            goto error;
    }

    if (EVP_EncryptUpdate(ctx, &ivcttag[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttag[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    if (!md) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tagl,
                                &ivcttag[*ivl + *ctl]) <= 0)
            goto error;
    } else {
        uint8_t hsh[EVP_MD_size(md)];
        HMAC_CTX hctx = {};
        uint64_t al = 0;

        if (HMAC_Init(&hctx, key, ksz / 2, md) <= 0)
            goto error;

        if (HMAC_Update(&hctx, (uint8_t *) aad, strlen(aad)) <= 0)
            goto error;

        if (HMAC_Update(&hctx, ivcttag, *ivl) <= 0)
            goto error;

        if (HMAC_Update(&hctx, &ivcttag[*ivl], *ctl) <= 0)
            goto error;

        al = htobe64(strlen(aad) * 8);
        if (HMAC_Update(&hctx, (uint8_t *) &al, sizeof(al)) <= 0)
            goto error;

        if (HMAC_Final(&hctx, hsh, NULL) <= 0)
            goto error;

        memcpy(&ivcttag[*ivl + *ctl], hsh, *tagl);
    }

    EVP_CIPHER_CTX_free(ctx);
    return ivcttag;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ivcttag);
    return NULL;
}

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
    uint8_t *ivcttag = NULL;
    const char *aad = NULL;
    json_t *tmp = NULL;
    json_t *p = NULL;
    json_t *a = NULL;
    bool ret = false;
    char *enc = NULL;
    size_t tagl = 0;
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

    a = json_pack("s++", json_string_value(p), aad ? "." : "", aad ? aad : "");
    if (!a)
        goto egress;

    ivcttag = encrypt(enc, json_string_value(a), pt, ptl,
                      cek, &ivl, &ctl, &tagl);
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

    if (tagl > 0) {
        tmp = jose_b64_encode_json(&ivcttag[ivl + ctl], tagl);
        if (json_object_set_new(jwe, "tag", tmp) == -1)
            goto egress;
    }

    ret = true;

egress:
    json_decref(a);
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
