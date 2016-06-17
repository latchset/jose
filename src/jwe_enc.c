/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "conv.h"
#include "cek_int.h"

#include <openssl/evp.h>

#include <string.h>

static uint8_t *
encrypt(const jose_cek_t *cek, const char *enc,
        uint8_t *aad, size_t aadl, uint8_t *pt, size_t ptl,
        size_t *ivl, size_t *ctl, size_t *tagl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ivcttag = NULL;
    int len;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", NULL)) {
    case 0: cph = EVP_aes_128_gcm(); *ivl = 12; *tagl = 16; break;
    case 1: cph = EVP_aes_192_gcm(); *ivl = 12; *tagl = 16; break;
    case 2: cph = EVP_aes_256_gcm(); *ivl = 12; *tagl = 16; break;
    default: return NULL;
    }

    ivcttag = malloc(*ivl + *tagl + ptl * 2);
    if (!ivcttag)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) <= 0)
        goto error;

    if (EVP_EncryptInit(ctx, NULL, cek->buf, ivcttag) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadl) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, &ivcttag[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttag[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            &ivcttag[*ivl + *ctl]) <= 0)
        goto error;

    EVP_CIPHER_CTX_free(ctx);
    return ivcttag;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ivcttag);
    return NULL;
}

jose_cek_t *
jose_jwe_encrypt(json_t *jwe, const json_t *prot, const json_t *shrd,
                 const uint8_t pt[], size_t ptlen)
{
    jose_cek_t *cek = NULL;
    const char *enc = NULL;
    json_t *p = NULL;
    json_t *s = NULL;

    p = json_deep_copy(prot);
    if (prot && !p)
        goto egress;

    s = json_deep_copy(prot);
    if (shrd && !s)
        goto egress;

    if (json_unpack(p, "{s: s}", "enc", &enc) == -1 &&
        json_unpack(s, "{s: s}", "enc", &enc) == -1) {
        enc = "A128CBC-HS256";

        if (!p && !s)
            p = json_object();

        if (json_object_set_new(p ? p : s, "enc", json_string(enc)) == -1)
            goto egress;
    }

    

egress:
    json_decref(p);
    json_decref(s);
    return cek;
}

jose_cek_t *
jose_jwe_encrypt_json(json_t *jwe, const json_t *prot, const json_t *shrd,
                      const json_t *pt, int flags)
{
    jose_cek_t *cek = NULL;
    char *ept = NULL;

    ept = json_dumps(pt, flags);
    if (!ept)
        return NULL;

    cek = jose_jwe_encrypt(jwe, prot, shrd, (uint8_t *) ept, strlen(ept));
    free(ept);
    return cek;
}

bool
jose_jwe_seal_key(json_t *jwe, const jose_cek_t *cek, const json_t *head,
                  EVP_PKEY *key)
{
    return false;
}

bool
jose_jwe_seal_jwk(json_t *jwe, const jose_cek_t *cek, const json_t *head,
                  const json_t *jwks)
{
    return false;
}
