/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jws.h"
#include "jwk.h"
#include "b64.h"
#include "conv.h"

#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <string.h>

static bool
add_sig(json_t *jws, json_t *sig)
{
    json_t *signatures = NULL;
    json_t *signature = NULL;
    json_t *protected = NULL;
    json_t *header = NULL;

    if (json_unpack(sig, "{s: o, s? o, s? o}", "signature", &signature,
                    "protected", &protected, "header", &header) == -1)
        return false;

    if (json_object_size(header) == 0 && json_string_length(protected) == 0)
        return false;

    signature = NULL;
    protected = NULL;
    header = NULL;

    if (json_unpack(jws, "{s? o, s? o, s? o, s? o}",
                    "signatures", &signatures, "signature", &signature,
                    "protected", &protected, "header", &header) == -1)
        return false;

    if (signatures) {
        if (!json_is_array(signatures))
            return false;

        if (json_array_size(signatures) == 0) {
            if (json_object_del(jws, "signatures") == -1)
                return false;

            signatures = NULL;
        }
    }

    /* If we have a sig in flattened format, migrate to general format. */
    if (signature) {
        json_t *obj = NULL;

        if (!signatures) {
            signatures = json_array();
            if (json_object_set_new(jws, "signatures", signatures) == -1)
                return false;
        }

        obj = json_pack("{s: O}", "signature", signature);
        if (json_array_append_new(signatures, obj) == -1)
            return false;

        if (json_object_del(jws, "signature") == -1)
            return false;

        if (protected) {
            if (json_object_set(obj, "protected", protected) == -1)
                return false;

            if (json_object_del(jws, "protected") == -1)
                return false;
        }

        if (header) {
            if (json_object_set(obj, "header", header) == -1)
                return false;

            if (json_object_del(jws, "header") == -1)
                return false;
        }
    }

    /* If we have some signatures already, append to the array. */
    if (signatures)
        return json_array_append(signatures, sig) == 0;

    return json_object_update(jws, sig) == 0;
}

static const char *
suggest(EVP_PKEY *key)
{
    size_t len = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        if (!EVP_PKEY_get0_hmac(key, &len))
            return NULL;

        len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;

        switch (len & (SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH)) {
        case SHA512_DIGEST_LENGTH: return "HS512";
        case SHA384_DIGEST_LENGTH: return "HS384";
        case SHA256_DIGEST_LENGTH: return "HS256";
        default: return NULL;
        }

    case EVP_PKEY_RSA:
        len = RSA_size(key->pkey.rsa) / 8;

        len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;

        switch (len & (SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH)) {
        case SHA512_DIGEST_LENGTH: return "RS512";
        case SHA384_DIGEST_LENGTH: return "RS384";
        case SHA256_DIGEST_LENGTH: return "RS256";
        default: return NULL;
        }

    case EVP_PKEY_EC:
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
        case NID_X9_62_prime256v1: return "ES256";
        case NID_secp384r1:        return "ES384";
        case NID_secp521r1:        return "ES512";
        default: return NULL;
        }

    default:
        return NULL;
    }
}

/* NOTE: This is not static because it is used by verify() for HMAC. */
jose_buf_t *
sign(const char *prot, const char *payl, EVP_PKEY *key, const char *alg);

jose_buf_t *
sign(const char *prot, const char *payl, EVP_PKEY *key, const char *alg)
{
    EVP_PKEY_CTX *pctx = NULL;
    ECDSA_SIG *ecdsa = NULL;
    const EVP_MD *md = NULL;
    const char *req = NULL;
    EVP_MD_CTX *ctx = NULL;
    jose_buf_t *sig = NULL;
    size_t len = 0;
    int pad = 0;

    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_HMAC:
        switch (str_to_enum(alg, "HS256", "HS384", "HS512", NULL)) {
        case 0: md = EVP_sha256(); break;
        case 1: md = EVP_sha384(); break;
        case 2: md = EVP_sha512(); break;
        default: return NULL;
        }
        break;

    case EVP_PKEY_RSA:
        /* Don't use small keys. RFC 7518 3.3 */
        if (RSA_size(key->pkey.rsa) < 2048 / 8)
            return NULL;

        switch (str_to_enum(alg, "RS256", "RS384", "RS512",
                            "PS256", "PS384", "PS512", NULL)) {
        case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
        case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
        case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
        case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
        case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
        case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
        default: return NULL;
        }
        break;

    case EVP_PKEY_EC:
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
        case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
        case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
        case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
        default: return NULL;
        }

        if (strcmp(alg, req) != 0)
            return NULL;
        break;

    default:
        return NULL;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return NULL;

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, key) < 0)
        goto error;

    if (pad != 0 && EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, prot, strlen(prot)) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, ".", 1) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, payl, strlen(payl)) < 0)
        goto error;

    if (EVP_DigestSignFinal(ctx, NULL, &len) < 0)
        goto error;

    sig = jose_buf_new(len, false);
    if (!sig)
        goto error;

    if (EVP_DigestSignFinal(ctx, sig->data, &sig->used) < 0)
        goto error;

    /* We have to special-case ECDSA signatures: the format is different. */
    if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
        const EC_GROUP *grp = NULL;

        ecdsa = d2i_ECDSA_SIG(NULL, &(const uint8_t *) { sig->data },
                              sig->used);
        if (!ecdsa)
            goto error;

        grp = EC_KEY_get0_group(key->pkey.ec);
        if (!grp)
            goto error;

        len = (EC_GROUP_get_degree(grp) + 7) / 8;

        if (!bn_encode(ecdsa->r, sig->data, len))
            goto error;

        if (!bn_encode(ecdsa->s, &sig->data[len], len))
            goto error;

        sig->used = len * 2;
    }

    EVP_MD_CTX_destroy(ctx);
    ECDSA_SIG_free(ecdsa);
    return sig;

error:
    EVP_MD_CTX_destroy(ctx);
    ECDSA_SIG_free(ecdsa);
    free(sig);
    return NULL;
}

static char *
choose_alg(json_t *sig, EVP_PKEY *key, const char *kalg)
{
    const int flags = JSON_SORT_KEYS | JSON_COMPACT;
    const char *alg = NULL;
    json_t *enc = NULL;
    json_t *dec = NULL;

    if (json_unpack(sig, "{s:{s:s}}", "protected", "alg", &alg) == 0)
        goto egress;

    enc = json_object_get(sig, "protected");
    dec = jose_b64_decode_json_load(enc, 0);
    if (json_is_string(enc) && !json_is_object(dec))
        goto egress;

    if (json_unpack(dec, "{s:s}", "alg", &alg) == 0)
        goto egress;

    if (json_unpack(sig, "{s:{s:s}}", "header", "alg", &alg) == 0)
        goto egress;

    alg = kalg;
    if (!alg)
        alg = suggest(key);
    if (!alg)
        goto egress;

    if (json_object_set_new(dec, "alg", json_string(alg)) == -1 ||
        json_object_set_new(sig, "protected",
                            jose_b64_encode_json_dump(dec, flags)) == -1)
        alg = NULL;

egress:
    if (alg) {
        if (!kalg || strcmp(kalg, alg) == 0)
            alg = strdup(alg);
        else
            alg = NULL;
    }
    json_decref(dec);
    return (char *) alg;
}

static bool
jws_sign(json_t *jws, EVP_PKEY *key, json_t *sig, const char *kalg)
{
    const char *payl = NULL;
    jose_buf_t *s = NULL;
    json_t *prot = NULL;
    char *alg = NULL;
    bool ret = false;

    if (!key)
        goto egress;

    if (json_unpack(jws, "{s:s}", "payload", &payl) == -1)
        goto egress;

    if (!json_is_object(sig)) {
        json_decref(sig);
        sig = json_object();
    }

    alg = choose_alg(sig, key, kalg);
    if (!alg)
        goto egress;

    prot = encode_protected(sig);
    if (!prot)
        goto egress;

    s = sign(json_is_string(prot) ? json_string_value(prot) : "",
             payl, key, alg);
    if (s) {
        json_t *tmp = jose_b64_encode_json_buf(s);
        if (json_object_set_new(sig, "signature", tmp) == -1)
            goto egress;

        ret = add_sig(jws, sig);
    }

egress:
    json_decref(sig);
    jose_buf_free(s);
    free(alg);
    return ret;
}

bool
jose_jws_sign(json_t *jws, EVP_PKEY *key, json_t *sig)
{
    return jws_sign(jws, key, sig, NULL);
}

bool
jose_jws_sign_jwk(json_t *jws, const json_t *jwk, json_t *sig)
{
    const char *kalg = NULL;
    EVP_PKEY *key = NULL;
    bool ret = false;

    if (!jose_jwk_use_allowed(jwk, "sig"))
        goto egress;

    if (!jose_jwk_op_allowed(jwk, "sign"))
        goto egress;

    if (json_unpack((json_t *) jwk, "{s?s}", "alg", &kalg) == -1)
        goto egress;

    key = jose_jwk_to_key(jwk);
    if (!key)
        goto egress;

    ret = jws_sign(jws, key, json_incref(sig), kalg);
    EVP_PKEY_free(key);

egress:
    json_decref(sig);
    return ret;
}
