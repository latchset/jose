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
seal(const char *alg, EVP_PKEY *cek, EVP_PKEY *key, size_t *cl)
{
    const uint8_t *c = NULL;
    uint8_t *ct = NULL;
    size_t clen = 0;
    int tmp = 0;

    c = EVP_PKEY_get0_hmac(cek, &clen);
    if (!c)
        return NULL;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC: {
        const EVP_CIPHER *cph = NULL;
        EVP_CIPHER_CTX *ctx = NULL;
        const uint8_t *k = NULL;
        size_t klen = 0;

        switch (str_to_enum(alg, "A128KW", "A192KW", "A256KW", NULL)) {
        case 0: cph = EVP_aes_128_wrap(); break;
        case 1: cph = EVP_aes_192_wrap(); break;
        case 2: cph = EVP_aes_256_wrap(); break;
        default: return NULL;
        }

        k = EVP_PKEY_get0_hmac(key, &klen);
        if (!k)
            return NULL;

        if ((int) klen != EVP_CIPHER_key_length(cph))
            return NULL;

        uint8_t iv[EVP_CIPHER_iv_length(cph)];
        memset(iv, 0xA6, EVP_CIPHER_iv_length(cph));

        ct = malloc(clen + EVP_CIPHER_block_size(cph) - 1);
        if (ct) {
            ctx = EVP_CIPHER_CTX_new();
            if (ctx) {
                if (EVP_EncryptInit(ctx, cph, k, iv) > 0) {
                    if (EVP_EncryptUpdate(ctx, ct, &tmp, c, clen) > 0) {
                        *cl = tmp;

                        if (EVP_EncryptFinal(ctx, &ct[tmp], &tmp) > 0) {
                            EVP_CIPHER_CTX_free(ctx);
                            *cl += tmp;
                            return ct;
                        }
                    }
                }

                EVP_CIPHER_CTX_free(ctx);
            }

            free(ct);
        }

        return NULL;
    }

    case EVP_PKEY_RSA: {
        int pad = 0;

        switch (str_to_enum(alg, "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", NULL)) {
        case 0: pad = RSA_PKCS1_PADDING; tmp = 11; break;
        case 1: pad = RSA_PKCS1_OAEP_PADDING; tmp = 41; break;
        default: return NULL;
        }

        if ((int) clen >= RSA_size(key->pkey.rsa) - tmp)
            return NULL;

        ct = malloc(RSA_size(key->pkey.rsa));
        if (!ct)
            return NULL;

        tmp = RSA_public_encrypt(clen, c, ct, key->pkey.rsa, pad);
        if (tmp < 0) {
            free(ct);
            return NULL;
        }

        return ct;
    }

    default:
        return NULL;
    }
}

static bool
add_seal(json_t *jwe, json_t *rcp)
{
    json_t *encrypted_key = NULL;
    json_t *recipients = NULL;
    json_t *header = NULL;

    if (json_unpack(jwe, "{s? o, s? o, s? o}",
                    "encrypted_key", &encrypted_key,
                    "recipients", &recipients,
                    "header", &header) == -1)
        return false;

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
    if (recipients)
        return json_array_append_new(recipients, rcp) == 0;

    return json_object_update_missing(jwe, rcp) == 0;
}

static const char *
suggest(EVP_PKEY *key)
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

    case EVP_PKEY_RSA: return "RSA-OAEP";
    default: return NULL;
    }
}

static char *
choose_alg(json_t *jwe, EVP_PKEY *key, json_t *rcp, const char *kalg)
{
    const char *alg = NULL;
    json_t *p = NULL;
    json_t *s = NULL;
    json_t *h = NULL;

    if (json_unpack(jwe, "{s?O,s?o}", "protected", &p,
                    "unprotected", &s) == -1)
        return NULL;

    if (json_is_string(p)) {
        json_t *dec = jose_b64_decode_json_load(p, 0);
        json_decref(p);
        p = dec;
    }

    if (p && !json_is_object(p))
        goto egress;

    if (json_unpack(p, "{s:s}", "alg", &alg) == 0)
        goto egress;

    if (json_unpack(s, "{s:s}", "alg", &alg) == 0)
        goto egress;

    if (json_unpack(rcp, "{s:{s:s}}", "header", "alg", &alg) == 0)
        goto egress;

    alg = kalg;
    if (!alg)
        alg = suggest(key);

    h = json_object_get(rcp, "header");
    if (!h && json_object_set_new(rcp, "header", h = json_object()) == -1) {
        alg = NULL;
        goto egress;
    }

    if (json_object_set_new(h, "alg", json_string(alg)) == -1)
        alg = NULL;

egress:
    if (alg) {
        if (!kalg || strcmp(kalg, alg) == 0)
            alg = strdup(alg);
        else
            alg = NULL;
    }
    json_decref(p);
    return (char *) alg;
}

static bool
jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp,
         const char *kalg)
{
    uint8_t *ct = NULL;
    char *alg = NULL;
    bool ret = false;
    size_t cl = 0;

    if (!rcp)
        rcp = json_object();

    if (json_is_object(rcp)) {
        alg = choose_alg(jwe, key, rcp, kalg);
        if (alg) {
            ct = seal(alg, cek, key, &cl);
            if (ct) {
                json_t *tmp = jose_b64_encode_json(ct, cl);
                if (json_object_set_new(rcp, "encrypted_key", tmp) == 0)
                    ret = add_seal(jwe, rcp);
                free(ct);
            }
        }
    }

    json_decref(rcp);
    free(alg);
    return ret;
}

bool
jose_jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp)
{
    return jwe_seal(jwe, cek, key, rcp, NULL);
}

bool
jose_jwe_seal_jwk(json_t *jwe, EVP_PKEY *cek, const json_t *jwk, json_t *rcp)
{
    const char *alg = NULL;
    EVP_PKEY *key = NULL;
    bool ret = false;

    if (!jose_jwk_use_allowed(jwk, "enc"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "wrapKey"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &alg) == -1)
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (key)
        ret = jwe_seal(jwe, cek, key, json_incref(rcp), alg);

egress:
    EVP_PKEY_free(key);
    json_decref(rcp);
    return ret;
}
