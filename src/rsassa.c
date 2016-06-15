/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jws.h"
#include "conv.h"

#include <openssl/rsa.h>
#include <string.h>

static const char *
rsassa_suggest(const EVP_PKEY *key)
{
    int size = 0;

    if (!key)
        return NULL;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

   size = RSA_size(key->pkey.rsa) * 8;

   if (size >= 4096)
       return "RS512";

   if (size >= 3072)
       return "RS384";

   if (size >= 2048)
       return "RS256";

   return NULL;
}

static buf_t *
rsassa_sign(const EVP_PKEY *key, const char *alg, const char *data)
{
    const EVP_MD *md = NULL;
    unsigned int siglen = 0;
    buf_t *sig = NULL;

    if (!key)
        return NULL;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return NULL;

    /* Don't use small keys. RFC 7518 3.3 */
    if (RSA_size(key->pkey.rsa) < 2048 / 8)
        return NULL;

    switch (string_to_enum(alg, false, "RS256", "RS384", "RS512", NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return NULL;
    }

    uint8_t hsh[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
        return NULL;

    sig = buf_new(RSA_size(key->pkey.rsa), false);
    if (!sig)
        return NULL;

    siglen = sig->len;

    if (!RSA_sign(EVP_MD_type(md), hsh, EVP_MD_size(md),
                  sig->buf, &siglen, key->pkey.rsa)) {
        buf_free(sig);
        return NULL;
    }

    sig->len = siglen;
    return sig;
}

static bool
rsassa_verify(const EVP_PKEY *key, const char *alg, const char *data,
              const uint8_t sig[], size_t slen)
{
    const EVP_MD *md = NULL;

    if (!key)
        return false;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
        return false;

    /* Note that although RFC 7518 3.3 says we shouldn't use small keys,
     * in the interest of being liberal in the data that we receive we
     * allow small keys only for verification. */

    if (RSA_size(key->pkey.rsa) != (int) slen)
        return false;

    for (size_t i = 0; i < 3; i++) {
        if (alg && string_to_enum(alg, false, "RS256",
                                  "RS384", "RS512", NULL) != i)
            continue;

        switch (i) {
        case 0: md = EVP_sha256(); break;
        case 1: md = EVP_sha384(); break;
        case 2: md = EVP_sha512(); break;
        }

        uint8_t hsh[EVP_MD_size(md)];

        if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
            return false;

        if (RSA_verify(EVP_MD_type(md), hsh, sizeof(hsh),
                       sig, slen, key->pkey.rsa) == 1)
            return true;
    }

    return false;
}

static jose_jws_alg_t rsassa = {
    .priority = UINT8_MAX / 2,
    .algorithms = (const char * const []) { "RS256", "RS384", "RS512", NULL },
    .suggest = rsassa_suggest,
    .sign = rsassa_sign,
    .verify = rsassa_verify,
};

static void __attribute__((constructor))
constructor(void)
{
    jose_jws_alg_register(&rsassa);
}
