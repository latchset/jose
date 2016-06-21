/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <string.h>

static size_t
min(size_t a, size_t b)
{
    return a > b ? b : a;
}

static ssize_t
decrypt(const char *enc, const char aad[], EVP_PKEY *cek, const uint8_t iv[],
        size_t ivl, const uint8_t ct[], size_t ctl, uint8_t tg[], size_t tgl,
        uint8_t pt[])
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    const uint8_t *c = NULL;
    HMAC_CTX hctx = {};
    ssize_t ptl = 0;
    size_t clen = 0;
    size_t tagl = 0;
    size_t keyl = 0;
    int len = 0;

    if (!enc || !iv || !aad || !ct || !tg || !cek)
        return -1;

    c = EVP_PKEY_get0_hmac(cek, &clen);
    if (!c)
        return -1;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM",
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        NULL)) {
    case 0: cph = EVP_aes_128_gcm(); tagl = 16; break;
    case 1: cph = EVP_aes_192_gcm(); tagl = 16; break;
    case 2: cph = EVP_aes_256_gcm(); tagl = 16; break;
    case 3: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 4: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 5: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return -1;
    }

    keyl = EVP_CIPHER_key_length(cph) * (md ? 2 : 1);
    tagl = md ? (size_t) EVP_MD_size(md) / 2 : tagl;

    uint8_t skey[keyl];
    uint8_t siv[EVP_CIPHER_iv_length(cph)];
    uint8_t stag[tagl];

    HMAC_CTX_init(&hctx);

    if (RAND_bytes(skey, sizeof(skey)) <= 0)
        goto error;
    if (RAND_bytes(stag, sizeof(stag)) <= 0)
        goto error;
    if (RAND_bytes(siv, sizeof(siv)) <= 0)
        goto error;

    memcpy(skey, c, min(clen, sizeof(skey)));
    memcpy(stag, tg, min(tgl, sizeof(stag)));
    memcpy(siv, iv, min(ivl, sizeof(siv)));

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_DecryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (EVP_DecryptInit(ctx, NULL, md ? &skey[sizeof(skey) / 2] : skey,
                        siv) <= 0)
        goto error;

    if (!md && EVP_DecryptUpdate(ctx, NULL, &len,
                                 (uint8_t *) aad, strlen(aad)) <= 0)
        goto error;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctl) <= 0)
        goto error;
    ptl = len;

    if (!md && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagl, stag) <= 0)
        goto error;

    if (EVP_DecryptFinal(ctx, &pt[ptl], &len) <= 0)
        goto error;
    ptl += len;

    if (md) {
        uint8_t hsh[EVP_MD_size(md)];
        uint64_t al = 0;

        if (HMAC_Init(&hctx, skey, sizeof(skey) / 2, md) <= 0)
            goto error;

        if (HMAC_Update(&hctx, (uint8_t *) aad, strlen(aad)) <= 0)
            goto error;

        if (HMAC_Update(&hctx, siv, sizeof(siv)) <= 0)
            goto error;

        if (HMAC_Update(&hctx, ct, ctl) <= 0)
            goto error;

        al = htobe64(strlen(aad) * 8);
        if (HMAC_Update(&hctx, (uint8_t *) &al, sizeof(al)) <= 0)
            goto error;

        if (HMAC_Final(&hctx, hsh, NULL) <= 0)
            goto error;

        if (CRYPTO_memcmp(hsh, stag, tagl) != 0)
            goto error;
    }

    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_cleanup(&hctx);
    return ptl;

error:
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_cleanup(&hctx);
    return -1;
}

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
    json_t *a = NULL;
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

    a = json_pack("s++", json_string_length(prot) > 0
                             ? json_string_value(prot) : "",
                  aad ? "." : "", aad ? aad : "");
    if (!a)
        goto egress;


    iv = decode(eiv, &ivl);
    ct = decode(ect, &ctl);
    tg = decode(etg, &tgl);
    if (iv && ct && tg) {
        ptl = decrypt(enc, json_string_value(a), cek,
                      iv, ivl, ct, ctl, tg, tgl, pt);
    }

egress:
    json_decref(p);
    json_decref(a);
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
