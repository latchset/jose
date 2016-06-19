/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <string.h>

static uint8_t *
encrypt(const char *enc, const char aad[], const uint8_t pt[], size_t ptl,
        jose_buf_t **cek, size_t *ivl, size_t *ctl, size_t *tagl)
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

    if (*cek) {
        if ((int) (*cek)->used != EVP_CIPHER_key_length(cph))
            goto error;
    } else {
        *cek = jose_buf_new(EVP_CIPHER_key_length(cph), true);
        if (!*cek)
            goto error;

        if (RAND_bytes((*cek)->data, (*cek)->used) <= 0)
            goto error;
    }

    ivcttag = malloc(*ivl + *tagl + ptl + EVP_CIPHER_block_size(cph) -1);
    if (!ivcttag)
        goto error;

    if (RAND_bytes(ivcttag, *ivl) <= 0)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, *ivl, NULL) <= 0)
        goto error;

    if (EVP_EncryptInit(ctx, NULL, (*cek)->data, ivcttag) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, NULL, &len, (uint8_t *) aad, strlen(aad)) <= 0)
        goto error;

    if (EVP_EncryptUpdate(ctx, &ivcttag[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttag[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tagl,
                            &ivcttag[*ivl + *ctl]) <= 0)
        goto error;

    EVP_CIPHER_CTX_free(ctx);
    return ivcttag;

error:
    EVP_CIPHER_CTX_free(ctx);
    jose_buf_free(*cek);
    free(ivcttag);
    *cek = NULL;
    return NULL;
}

static const char *
suggest_encrypt(const jose_buf_t *cek)
{
    switch (cek ? cek->used * 8 : 128) {
    case 128: return "A128GCM";
    case 192: return "A192GCM";
    case 256: return "A256GCM";
    default: return NULL;
    }
}

bool
jose_jwe_encrypt(json_t *jwe, const json_t *prot, const json_t *shrd,
                 const uint8_t pt[], size_t ptl, jose_buf_t **cek)
{
    uint8_t *ivcttag = NULL;
    const char *enc = NULL;
    const char *aad = NULL;
    json_t *tmp = NULL;
    json_t *p = NULL;
    json_t *s = NULL;
    json_t *e = NULL;
    json_t *a = NULL;
    size_t tagl = 0;
    size_t ctl = 0;
    size_t ivl = 0;

    if (json_unpack(jwe, "{s? s}", "aad", &aad) == -1)
        return NULL;

    p = json_deep_copy(prot);
    if (prot && !p)
        goto egress;

    s = json_deep_copy(prot);
    if (shrd && !s)
        goto egress;

    if (json_unpack(p, "{s: s}", "enc", &enc) == -1 &&
        json_unpack(s, "{s: s}", "enc", &enc) == -1) {
        enc = suggest_encrypt(*cek);

        if (!p && !s)
            p = json_object();

        if (json_object_set_new(p ? p : s, "enc", json_string(enc)) == -1)
            goto egress;
    }

    e = jose_b64_encode_json_dump(p, JSON_SORT_KEYS | JSON_COMPACT);
    if (p && !e)
        goto egress;

    a = json_pack("s++", json_string_value(e), aad ? "." : "", aad ? aad : "");
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

    if (p && json_object_set(jwe, "protected", p) == -1)
        goto egress;

    if (s && json_object_set(jwe, "unprotected", s) == -1)
        goto egress;

egress:
    json_decref(p);
    json_decref(s);
    json_decref(e);
    json_decref(a);
    free(ivcttag);
    return cek;
}

bool
jose_jwe_encrypt_json(json_t *jwe, const json_t *prot, const json_t *shrd,
                      const json_t *pt, int flags, jose_buf_t **cek)
{
    char *ept = NULL;
    bool ret = false;

    ept = json_dumps(pt, flags);
    if (!ept)
        return NULL;

    ret = jose_jwe_encrypt(jwe, prot, shrd, (uint8_t *) ept, strlen(ept), cek);
    free(ept);
    return ret;
}

static uint8_t *
seal(const char *alg, const jose_buf_t *cek, EVP_PKEY *key, size_t *len)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *out = NULL;
    uint8_t *iv = NULL;
    size_t klen = 0;
    int pad = 0;
    int tmp = 0;

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

        out = malloc(cek->used + EVP_CIPHER_block_size(cph) - 1);
        if (!out)
            goto error;

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            goto error;

        if (EVP_EncryptInit(ctx, cph, k, iv) <= 0)
            goto error;

        if (EVP_EncryptUpdate(ctx, out, &tmp, cek->data, cek->used) <= 0)
            goto error;
        *len = tmp;

        if (EVP_EncryptFinal(ctx, &out[*len], &tmp) <= 0)
            goto error;
        *len += tmp;

        EVP_CIPHER_CTX_free(ctx);
        return out;


    case EVP_PKEY_RSA:
        switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
        case 0: pad = RSA_PKCS1_PADDING; tmp = 11; break;
        case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; break;
        default: return NULL;
        }

        if ((int) cek->used >= RSA_size(key->pkey.rsa) - tmp)
            return NULL;

        out = malloc(RSA_size(key->pkey.rsa));
        if (!out)
            return NULL;

        tmp = RSA_public_encrypt(cek->used, cek->data, out,
                                 key->pkey.rsa, pad);
        if (tmp < 0) {
            free(out);
            return NULL;
        }

        *len = tmp;
        return out;

    default:
        return NULL;
    }

error:
    EVP_CIPHER_CTX_free(ctx);
    free(out);
    return NULL;
}

static bool
add_seal(json_t *jwe, json_t *head, const uint8_t *seal, size_t len)
{
    json_t *encrypted_key = NULL;
    json_t *unprotected = NULL;
    json_t *recipients = NULL;
    json_t *protected = NULL;
    json_t *header = NULL;
    json_t *p = NULL;

    if (seal)
        return false;

    if (json_unpack(jwe, "{s? s, s? o, s? o, s? s, s? o}",
                    "encrypted_key", &encrypted_key,
                    "unprotected", &unprotected,
                    "recipients", &recipients,
                    "protected", &protected,
                    "header", &header) == -1)
        return false;

    p = jose_b64_decode_json_load(protected, 0);
    if (protected && !p)
        return false;

    if (json_object_size(p) == 0 &&
        json_object_size(unprotected) == 0 &&
        json_object_size(head) == 0) {
        json_decref(p);
        return false;
    }
    json_decref(p);

    if (recipients) {
        if (!json_is_array(recipients))
            return false;

        if (json_array_size(recipients) == 0) {
            if (json_object_del(jwe, "recipients") == -1)
                return false;

            recipients = NULL;
        }
    }

    /* If we have a jwe in flattened format, migrate to general format. */
    if (encrypted_key) {
        json_t *obj = NULL;

        if (!recipients) {
            recipients = json_array();
            if (json_object_set_new(jwe, "recipients", recipients) == -1)
                return false;
        }

        obj = json_pack("{s: O}", "encrypted_key", encrypted_key);
        if (json_array_append_new(recipients, obj) == -1)
            return false;

        if (json_object_del(jwe, "encrypted_key") == -1)
            return false;

        if (header) {
            if (json_object_set(obj, "header", header) == -1)
                return false;

            if (json_object_del(jwe, "header") == -1)
                return false;
        }
    }

    /* If we have some recipients already, append to the array. */
    if (recipients) {
        json_t *obj = NULL;

        obj = json_object();
        if (json_array_append_new(recipients, obj) == -1)
            return false;

        jwe = obj;
    }

    encrypted_key = jose_b64_encode_json(seal, len);
    if (json_object_set_new(jwe, "encrypted_key", encrypted_key) < 0)
        return false;

    if (json_object_size(head) > 0 &&
        json_object_set(jwe, "header", head) < 0)
        return false;

    return true;
}

static const char *
suggest_seal(EVP_PKEY *key)
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

    case EVP_PKEY_RSA:
        return "RSA-OAEP";

    default:
        return NULL;
    }
}

bool
jose_jwe_seal(json_t *jwe, const jose_buf_t *cek, const json_t *head,
              EVP_PKEY *key)
{
    const json_t *prot = NULL;
    const char *alg = NULL;
    uint8_t *ct = NULL;
    json_t *h = NULL;
    json_t *p = NULL;
    bool ret = false;
    size_t ctl = 0;

    h = json_deep_copy(head);
    if (head && !h)
        goto error;

    prot = json_object_get(jwe, "protected");
    if (prot) {
        p = jose_b64_decode_json_load(prot, 0);
        if (!p)
            goto error;

        if (json_unpack(p, "{s? s}", "alg", &alg) == -1)
            goto error;
    }

    if (!alg) {
        if (json_unpack(jwe, "{s:{s:s}}", "unprotected", "alg", &alg) == -1 &&
            json_unpack((json_t *) head, "{s:s}", "alg", &alg) == -1) {
            alg = suggest_seal(key);
            if (!alg)
                goto error;

            if (!h)
                h = json_object();

            if (json_object_set_new(h, "alg", json_string(alg)) == -1)
                goto error;
        }
    }

    ct = seal(alg, cek, key, &ctl);
    if (ct)
        ret = add_seal(jwe, h, ct, ctl);

error:
    json_decref(h);
    json_decref(p);
    return ret;
}

static bool
seal_jwk(json_t *jwe, const jose_buf_t *cek, const json_t *head,
          const json_t *jwk, const char *flags)
{
    const char *alg = NULL;
    EVP_PKEY *key = NULL;
    json_t *prot = NULL;
    json_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;
    bool ret = false;

    if (json_unpack(jwe, "{s? o, s? o}",
                    "protected", &prot,
                    "unprotected", &s) == -1)
        return false;

    p = jose_b64_decode_json_load(prot, 0);
    if (prot && !p)
        return false;

    h = json_deep_copy(head);
    if (head && !h)
        goto egress;

    if (!h && has_flags(flags, false, "KI"))
        h = json_object();

    if (has_flags(flags, false, "K") && !json_object_get(h, "jwk")) {
        json_t *copy = jose_jwk_dup(jwk, false);
        if (json_object_set_new(h, "jwk", copy) == -1)
            goto egress;
    }

    if (has_flags(flags, false, "I") && !json_object_get(h, "kid")) {
        json_t *kid = json_object_get(jwk, "kid");
        if (kid && json_object_set(h, "kid", kid) == -1)
            goto egress;
    }

    if (json_unpack(p, "{s: s}", "alg", &alg) == -1 &&
        json_unpack(s, "{s: s}", "alg", &alg) == -1 &&
        json_unpack(h, "{s: s}", "alg", &alg) == -1) {
        if (json_unpack((json_t *) jwk, "{s: s}", "alg", &alg) == 0) {
            if (!h && !p)
                p = json_object();

            if (json_object_set_new(h, "alg", json_string(alg)) == -1)
                goto egress;
        }
    }

    key = jose_jwk_to_key(jwk);
    if (key)
        ret = jose_jwe_seal(jwe, cek, h, key);

egress:
    EVP_PKEY_free(key);
    json_decref(p);
    json_decref(h);
    return ret;
}

bool
jose_jwe_seal_jwk(json_t *jwe, const jose_buf_t *cek, const json_t *head,
                  const json_t *jwks, const char *flags)
{
    const json_t *array = NULL;

    if (!jwe || !cek || !jwks)
        return false;

    if (json_is_array(jwks))
        array = jwks;
    else if (json_is_array(json_object_get(jwks, "keys")))
        array = json_object_get(jwks, "keys");

    if (json_is_array(array)) {
        for (size_t i = 0; i < json_array_size(array); i++) {
            const json_t *jwk = json_array_get(array, i);

            if (!seal_jwk(jwe, cek, head, jwk, flags))
                return false;
        }

        return json_array_size(array) > 0;
    }

    return seal_jwk(jwe, cek, head, jwks, flags);
}
