/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "rsassa.h"
#include "conv.h"

#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>

const char *
rsassa_suggest(EVP_PKEY *key)
{
    size_t len = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Round down to the nearest hash size. */
    len = RSA_size(key->pkey.rsa) / 8;
    len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;
    len &= SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH;

    switch (len) {
    case SHA512_DIGEST_LENGTH: return "RS512";
    case SHA384_DIGEST_LENGTH: return "RS384";
    case SHA256_DIGEST_LENGTH: return "RS256";
    default: return NULL;
    }
}

uint8_t *
rsassa_sign(const char *alg, EVP_PKEY *key, const char *prot,
            const char *payl, size_t *len)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    uint8_t *sig = NULL;
    int pad = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

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
    default: return 0;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return NULL;

    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, key) < 0)
        goto error;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, prot, strlen(prot)) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, ".", 1) < 0)
        goto error;

    if (EVP_DigestSignUpdate(ctx, payl, strlen(payl)) < 0)
        goto error;

    if (EVP_DigestSignFinal(ctx, NULL, len) < 0)
        goto error;

    sig = malloc(*len);
    if (!sig)
        goto error;

    if (EVP_DigestSignFinal(ctx, sig, len) < 0)
        goto error;

    EVP_MD_CTX_destroy(ctx);
    return sig;

error:
    EVP_MD_CTX_destroy(ctx);
    free(sig);
    return NULL;
}

bool
rsassa_verify(const char *alg, EVP_PKEY *key, const char *prot,
              const char *payl, const uint8_t sig[], size_t len)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    bool ret = false;
    int pad = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Note that although RFC 7518 3.3 says we shouldn't use small keys,
     * in the interest of being liberal in the data that we receive, we
     * allow small keys only for verification. */

    switch (str_to_enum(alg, "RS256", "RS384", "RS512",
                        "PS256", "PS384", "PS512", NULL)) {
    case 0: md = EVP_sha256(); pad = RSA_PKCS1_PADDING; break;
    case 1: md = EVP_sha384(); pad = RSA_PKCS1_PADDING; break;
    case 2: md = EVP_sha512(); pad = RSA_PKCS1_PADDING; break;
    case 3: md = EVP_sha256(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 4: md = EVP_sha384(); pad = RSA_PKCS1_PSS_PADDING; break;
    case 5: md = EVP_sha512(); pad = RSA_PKCS1_PSS_PADDING; break;
    default: return false;
    }

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto egress;

    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, key) < 0)
        goto egress;

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, pad) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, prot, strlen(prot)) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, ".", 1) < 0)
        goto egress;

    if (EVP_DigestVerifyUpdate(ctx, payl, strlen(payl)) < 0)
        goto egress;

    ret = EVP_DigestVerifyFinal(ctx, sig, len) == 1;

egress:
    EVP_MD_CTX_destroy(ctx);
    return ret;
}
