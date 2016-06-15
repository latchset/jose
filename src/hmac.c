/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jws.h"
#include "conv.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

static const char *
hmac_suggest(EVP_PKEY *key)
{
    int len = 0;

    if (!key)
        return NULL;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_HMAC)
        return NULL;

    if (!EVP_PKEY_get_hmac(key, &len))
        return NULL;

    if (len > SHA512_DIGEST_LENGTH)
        return "HS512";

    if (len > SHA384_DIGEST_LENGTH)
        return "HS384";

    if (len > SHA256_DIGEST_LENGTH)
        return "HS256";

    return NULL;
}

static buf_t *
hmac_sign(EVP_PKEY *key, const char *alg, const char *data)
{
    const uint8_t *buf = NULL;
    const EVP_MD *md = NULL;
    buf_t *sig = NULL;
    int len = 0;

    if (!key)
        return NULL;

    buf = EVP_PKEY_get_hmac(key, &len);
    if (!buf)
        return NULL;

    switch (string_to_enum(alg, false, "HS256", "HS384", "HS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return NULL;
    }

    sig = buf_new(EVP_MD_size(md), false);
    if (!sig)
        return NULL;

    if (!HMAC(md, buf, len, (uint8_t *) data, strlen(data), sig->buf, NULL)) {
        buf_free(sig);
        return NULL;
    }

    return sig;
}

static bool
hmac_verify(EVP_PKEY *key, const char *alg, const char *data,
            const uint8_t sig[], size_t slen)
{
    const uint8_t *buf = NULL;
    const EVP_MD *md = NULL;
    int len = 0;

    if (!key)
        return false;

    buf = EVP_PKEY_get_hmac(key, &len);
    if (!buf)
        return NULL;

    switch (slen) {
    case SHA256_DIGEST_LENGTH: md = EVP_sha256(); break;
    case SHA384_DIGEST_LENGTH: md = EVP_sha384(); break;
    case SHA512_DIGEST_LENGTH: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hmac[slen];

    if (!HMAC(md, buf, len, (uint8_t *) data, strlen(data), hmac, NULL))
        return false;

    return memcmp(hmac, sig, slen) == 0;
}

static jose_jws_alg_t hmac = {
    .priority = UINT8_MAX / 2,
    .algorithms = (const char * const []) { "HS256", "HS384", "HS512", NULL },
    .suggest = hmac_suggest,
    .sign = hmac_sign,
    .verify = hmac_verify
};

static void __attribute__((constructor))
constructor(void)
{
    jose_jws_alg_register(&hmac);
}
