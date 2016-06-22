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

static ssize_t
unseal(EVP_PKEY *key, const char *alg, const uint8_t ct[], size_t cl,
       uint8_t pt[])
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *iv = NULL;
    size_t klen = 0;
    ssize_t pl = -1;
    int pad = 0;
    int tmp = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        switch (str_to_enum(alg, "A128KW", "A192KW", "A256KW", NULL)) {
        case 0: cph = EVP_aes_128_wrap(); break;
        case 1: cph = EVP_aes_192_wrap(); break;
        case 2: cph = EVP_aes_256_wrap(); break;
        default: return -1;
        }

        k = EVP_PKEY_get0_hmac(key, &klen);
        if (!k)
            return -1;

        if ((int) klen != EVP_CIPHER_key_length(cph))
            return -1;

        iv = alloca(EVP_CIPHER_iv_length(cph));
        memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return -1;

        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        if (EVP_DecryptInit_ex(ctx, cph, NULL, k, iv) > 0) {
            if (EVP_DecryptUpdate(ctx, pt, &tmp, ct, cl) > 0) {
                pl = tmp;

                if (EVP_DecryptFinal(ctx, &pt[tmp], &tmp) > 0)
                    pl += tmp;
                else
                    pl = -1;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return pl;

    case EVP_PKEY_RSA:
        switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
        case 0: pad = RSA_PKCS1_PADDING; break;
        case 1: pad = RSA_PKCS1_OAEP_PADDING; break;
        default: return -1;
        }

        return RSA_private_decrypt(cl, ct, pt, key->pkey.rsa, pad);

    default:
        return -1;
    }
}

static EVP_PKEY *
unseal_recip(EVP_PKEY *key, const json_t *prot, const json_t *shrd,
             const json_t *rcp)
{
    const char *alg = NULL;
    EVP_PKEY *cek = NULL;
    uint8_t *ct = NULL;
    uint8_t *pt = NULL;
    json_t *ek = NULL;
    ssize_t pl = 0;
    size_t cl = 0;

    if (json_unpack((json_t *) prot, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) shrd, "{s: s}", "alg", &alg) == -1 &&
        json_unpack((json_t *) rcp, "{s: {s: s}}",
                    "header", "alg", &alg) == -1)
        return NULL;

    ek = json_object_get(rcp, "encrypted_key");
    if (!json_is_string(ek))
        return NULL;

    cl = jose_b64_dlen(json_string_length(ek));
    ct = malloc(cl);
    if (ct) {
        if (jose_b64_decode(json_string_value(ek), ct)) {
            pt = malloc(cl);
            if (pt) {
                pl = unseal(key, alg, ct, cl, pt);
                if (pl >= 0)
                    cek = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pt, pl);
                free(pt);
            }
        }
        free(ct);
    }

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
