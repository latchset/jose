/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "hmac.h"
#include "conv.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "string.h"

bool
hmac(const EVP_MD *md, const uint8_t key[], size_t klen, uint8_t hsh[], ...)
{
    unsigned int ign = 0;
    HMAC_CTX ctx = {};
    bool ret = false;
    va_list ap;

    va_start(ap, hsh);

    HMAC_CTX_init(&ctx);

    if (HMAC_Init(&ctx, key, klen, md) <= 0)
        goto egress;

    for (const char *data = NULL; (data = va_arg(ap, const char *)); ) {
        if (HMAC_Update(&ctx, (uint8_t *) data, strlen(data)) <= 0)
            goto egress;
    }

    ret = HMAC_Final(&ctx, hsh, &ign) > 0;

egress:
    HMAC_CTX_cleanup(&ctx);
    va_end(ap);
    return ret;
}

const char *
hmac_suggest(EVP_PKEY *key)
{
    size_t len = 0;

    if (!EVP_PKEY_get0_hmac(key, &len))
        return NULL;

    /* Round down to the nearest hash length. */
    len = len < SHA512_DIGEST_LENGTH ? len : SHA512_DIGEST_LENGTH;
    len &= SHA384_DIGEST_LENGTH | SHA256_DIGEST_LENGTH;

    switch (len) {
    case SHA512_DIGEST_LENGTH: return "HS512";
    case SHA384_DIGEST_LENGTH: return "HS384";
    case SHA256_DIGEST_LENGTH: return "HS256";
    default: return NULL;
    }
}

uint8_t *
hmac_sign(const char *alg, EVP_PKEY *key, const char *prot, const char *payl,
          size_t *len)
{
    const EVP_MD *md = NULL;
    const uint8_t *k = NULL;
    uint8_t *hsh = NULL;
    size_t kl = 0;

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    switch (str_to_enum(alg, "HS256", "HS384", "HS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return NULL;
    }

    *len = EVP_MD_size(md);
    hsh = malloc(*len);
    if (!hsh)
        return NULL;

    if (hmac(md, k, kl, hsh, prot ? prot : "", ".", payl ? payl : ".", NULL))
        return hsh;

    free(hsh);
    return NULL;
}

bool
hmac_verify(const char *alg, EVP_PKEY *key, const char *prot, const char *payl,
            const uint8_t sig[], size_t len)
{
    const uint8_t *k = NULL;
    uint8_t *tmp = NULL;
    uint8_t *hsh = NULL;
    bool ret = false;
    size_t hl = 0;
    size_t kl = 0;

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return false;

    hsh = hmac_sign(alg, key, prot, payl, &hl);
    if (!hsh)
        return false;

    tmp = malloc(hl);
    if (!tmp)
        goto egress;

    if (RAND_bytes(tmp, hl) <= 0)
        goto egress;

    ret = CRYPTO_memcmp(len == hl ? sig : tmp, hsh, hl) == 0;

egress:
    free(tmp);
    free(hsh);
    return ret;
}
