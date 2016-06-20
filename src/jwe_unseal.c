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

static jose_buf_t *
unseal(EVP_PKEY *key, const char *alg, const jose_buf_t *ct)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *iv = NULL;
    size_t klen = 0;
    int pad = 0;
    int tmp = 0;

    jose_buf_t *cek = NULL;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        switch (str_to_enum(alg, "A128KW", "A192KW", "A256KW", NULL)) {
        case 0: cph = EVP_aes_128_wrap(); break;
        case 1: cph = EVP_aes_192_wrap(); break;
        case 2: cph = EVP_aes_256_wrap(); break;
        default: return NULL;
        }

        k = EVP_PKEY_get0_hmac(key, &klen);
        if (!k)
            goto error;

        if ((int) klen != EVP_CIPHER_key_length(cph))
            goto error;

        iv = alloca(EVP_CIPHER_iv_length(cph));
        memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

        cek = jose_buf_new(ct->used, true);
        if (!cek)
            goto error;

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            goto error;

        if (EVP_DecryptInit(ctx, cph, k, iv) <= 0)
            goto error;

        if (EVP_DecryptUpdate(ctx, cek->data, &tmp, ct->data, ct->used) <= 0)
            goto error;
        cek->used = tmp;

        if (EVP_DecryptFinal(ctx, &cek->data[klen], &tmp) <= 0)
            goto error;
        cek->used += tmp;

        EVP_CIPHER_CTX_free(ctx);
        return cek;


    case EVP_PKEY_RSA:
        switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
        case 0: pad = RSA_PKCS1_PADDING; break;
        case 1: pad = RSA_PKCS1_OAEP_PADDING; break;
        default: return NULL;
        }

        cek = jose_buf_new(RSA_size(key->pkey.rsa), true);
        if (!cek)
            return NULL;

        tmp = RSA_private_decrypt(ct->used, ct->data, cek->data,
                                  key->pkey.rsa, pad);
        if (tmp < 0)
            goto error;

        cek->used = tmp;
        return cek;

    default:
        return NULL;
    }

error:
    EVP_CIPHER_CTX_free(ctx);
    jose_buf_free(cek);
    return NULL;
}

static EVP_PKEY *
unseal_recip(EVP_PKEY *key, const json_t *prot, const json_t *shrd,
             const json_t *rcp)
{
    const char *alg = NULL;
    jose_buf_t *ct = NULL;
    jose_buf_t *pt = NULL;
    EVP_PKEY *cek = NULL;

    if (json_unpack((json_t *) prot, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) shrd, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) rcp, "{s: {s: s}}",
                    "header", "alg", &alg) == -1)
        return NULL;

    ct = jose_b64_decode_json_buf(
        json_object_get(rcp,"encrypted_key"),
        false
    );
    if (!ct)
        return NULL;

    pt = unseal(key, alg, ct);
    jose_buf_free(ct);
    if (!pt)
        return NULL;

    cek = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pt->data, pt->used);
    jose_buf_free(pt);
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

    p = jose_b64_decode_json_load(prot, 0);
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
