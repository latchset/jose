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

jose_buf_t *
decrypt(const char *enc, const jose_buf_t *iv, const char aad[],
        const jose_buf_t *ct, const jose_buf_t *tag, const jose_buf_t *cek);

static size_t
min(size_t a, size_t b)
{
    return a > b ? b : a;
}

jose_buf_t *
decrypt(const char *enc, const jose_buf_t *iv, const char aad[],
        const jose_buf_t *ct, const jose_buf_t *tag, const jose_buf_t *cek)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    jose_buf_t *pt = NULL;
    HMAC_CTX hctx = {};
    size_t tagl = 0;
    size_t keyl = 0;
    int len = 0;

    HMAC_CTX_init(&hctx);

    if (!enc || !iv || !aad || !ct || !tag || !cek)
        return NULL;

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM",
                        "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                        NULL)) {
    case 0: cph = EVP_aes_128_gcm(); tagl = 16; break;
    case 1: cph = EVP_aes_192_gcm(); tagl = 16; break;
    case 2: cph = EVP_aes_256_gcm(); tagl = 16; break;
    case 3: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 4: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 5: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    keyl = EVP_CIPHER_key_length(cph) * (md ? 2 : 1);
    tagl = md ? (size_t) EVP_MD_size(md) / 2 : tagl;

    jose_buf_t *skey = jose_buf_new(keyl, true);
    uint8_t siv[EVP_CIPHER_iv_length(cph)];
    uint8_t stag[tagl];
    if (!skey)
        return NULL;

    if (RAND_bytes(skey->data, skey->used) <= 0)
        goto error;
    if (RAND_bytes(stag, sizeof(stag)) <= 0)
        goto error;
    if (RAND_bytes(siv, sizeof(siv)) <= 0)
        goto error;

    memcpy(skey->data, cek->data, min(cek->used, skey->used));
    memcpy(stag, tag->data, min(tag->used, sizeof(stag)));
    memcpy(siv, iv->data, min(iv->used, sizeof(siv)));

    /* Try to get a locked buffer. But don't error if we can't.
     * This is because the size of the plaintext may exceed the amount
     * of memory that is allowed to be locked. */
    pt = jose_buf_new(ct->used, true);
    if (!pt) {
        pt = jose_buf_new(ct->used, false);
        if (!pt)
            return NULL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_DecryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (EVP_DecryptInit(ctx, NULL,
                        md ? &skey->data[skey->used / 2] : skey->data,
                        siv) <= 0)
        goto error;

    if (!md && EVP_DecryptUpdate(ctx, NULL, &len,
                                 (uint8_t *) aad, strlen(aad)) <= 0)
        goto error;

    if (EVP_DecryptUpdate(ctx, pt->data, &len, ct->data, ct->used) <= 0)
        goto error;
    pt->used = len;

    if (!md && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagl, stag) <= 0)
        goto error;

    if (EVP_DecryptFinal(ctx, &pt->data[pt->used], &len) <= 0)
        goto error;
    pt->used += len;

    if (md) {
        uint8_t hsh[EVP_MD_size(md)];
        uint64_t al = 0;

        if (HMAC_Init(&hctx, skey->data, skey->used / 2, md) <= 0)
            goto error;

        if (HMAC_Update(&hctx, (uint8_t *) aad, strlen(aad)) <= 0)
            goto error;

        if (HMAC_Update(&hctx, siv, sizeof(siv)) <= 0)
            goto error;

        if (HMAC_Update(&hctx, ct->data, ct->used) <= 0)
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
    jose_buf_free(skey);
    return pt;

error:
    EVP_CIPHER_CTX_free(ctx);
    HMAC_CTX_cleanup(&hctx);
    jose_buf_free(skey);
    jose_buf_free(pt);
    return NULL;
}

static jose_buf_t *
unseal_recip(EVP_PKEY *key, const json_t *prot, const json_t *shrd,
             const json_t *rcp)
{
    const char *alg = NULL;
    jose_buf_t *ct = NULL;
    jose_buf_t *pt = NULL;

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
    return pt;
}

jose_buf_t *
jose_jwe_unseal(const json_t *jwe, EVP_PKEY *key)
{
    const json_t *prot = NULL;
    const json_t *shrd = NULL;
    const json_t *rcps = NULL;
    jose_buf_t *cek = NULL;
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

static jose_buf_t *
unseal_jwk(const json_t *jwe, const json_t *jwk)
{
    EVP_PKEY *key = NULL;
    jose_buf_t *cek = NULL;

    key = jose_jwk_to_key(jwk);
    if (!key)
        return NULL;

    cek = jose_jwe_unseal(jwe, key);
    EVP_PKEY_free(key);
    return cek;
}

jose_buf_t *
jose_jwe_unseal_jwk(const json_t *jwe, const json_t *jwks)
{
    const json_t *array = NULL;

    if (!jwe || !jwks)
        return false;

    if (json_is_array(jwks))
        array = jwks;
    else if (json_is_array(json_object_get(jwks, "keys")))
        array = json_object_get(jwks, "keys");

    if (json_is_array(array)) {
        jose_buf_t *cek = NULL;

        for (size_t i = 0; i < json_array_size(array) && !cek; i++) {
            const json_t *jwk = json_array_get(array, i);
            cek = unseal_jwk(jwe, jwk);
        }

        return cek;
    }

    return unseal_jwk(jwe, jwks);
}

jose_buf_t *
jose_jwe_decrypt(const json_t *jwe, const jose_buf_t *cek)
{
    const json_t *prot = NULL;
    const json_t *shrd = NULL;
    const json_t *jtag = NULL;
    const json_t *jiv = NULL;
    const json_t *jct = NULL;
    const char *aad = NULL;
    const char *enc = NULL;
    jose_buf_t *tag = NULL;
    jose_buf_t *ct = NULL;
    jose_buf_t *iv = NULL;
    jose_buf_t *pt = NULL;
    json_t *p = NULL;
    json_t *a = NULL;

    if (json_unpack((json_t *) jwe, "{s? o, s: o, s? o, s? s, s? o, s? o}",
                    "unprotected", &shrd,
                    "ciphertext", &jct,
                    "protected", &prot,
                    "aad", &aad,
                    "tag", &jtag,
                    "iv", &jiv) == -1)
        return NULL;

    p = jose_b64_decode_json_load(prot, 0);
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

    iv = jose_b64_decode_json_buf(jiv, false);
    if (jiv && !iv)
        goto egress;

    ct = jose_b64_decode_json_buf(jct, false);
    if (jct && !ct)
        goto egress;

    tag = jose_b64_decode_json_buf(jtag, false);
    if (jtag && !tag)
        goto egress;

    pt = decrypt(enc, iv, json_string_value(a), ct, tag, cek);

egress:
    jose_buf_free(tag);
    jose_buf_free(ct);
    jose_buf_free(iv);
    json_decref(p);
    json_decref(a);
    return pt;
}

json_t *
jose_jwe_decrypt_json(const json_t *jwe, const jose_buf_t *cek, int flags)
{
    jose_buf_t *pt = NULL;
    json_t *json = NULL;

    pt = jose_jwe_decrypt(jwe, cek);
    if (!pt)
        return NULL;

    json = json_loadb((char *) pt->data, pt->used, flags, NULL);
    jose_buf_free(pt);
    return json;
}
