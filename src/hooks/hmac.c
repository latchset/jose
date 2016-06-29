/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"
#include "../b64.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "HS256", "HS384", "HS512"

static bool
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

static bool
generate(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bytes = NULL;
    json_t *upd = NULL;
    json_int_t len = 0;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: len = 32; break;
    case 1: len = 48; break;
    case 2: len = 64; break;
    default: return true;
    }

    if (!kty) {
        if (json_object_set_new(jwk, "kty", json_string("oct")) == -1)
            return false;
    } else if (strcmp(kty, "oct") != 0)
        return false;

    if (!bytes) {
        if (json_object_set_new(jwk, "bytes", json_integer(len)) == -1)
            return false;
    } else if (!json_is_integer(bytes) || json_integer_value(bytes) < len)
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "sig", "key_ops",
                    "sign", "verify");
    if (!upd)
        return false;

    if (json_object_update_missing(jwk, upd) == -1) {
        json_decref(upd);
        return false;
    }

    json_decref(upd);
    return true;
}

static const char *
suggest(const json_t *jwk)
{
    const char *kty = NULL;
    const char *k = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    len = jose_b64_dlen(strlen(k));

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

static uint8_t *
sign(const char *alg, EVP_PKEY *key,
        const char *prot, const char *payl,
        size_t *sigl)
{
    const EVP_MD *md = NULL;
    const uint8_t *k = NULL;
    uint8_t *sig = NULL;
    size_t kl = 0;

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return NULL;
    }

    *sigl = EVP_MD_size(md);

    if (kl < *sigl)
        return NULL;

    sig = malloc(*sigl);
    if (!sig)
        return NULL;

    if (hmac(md, k, kl, sig,
             prot ? prot : "", ".",
             payl ? payl : ".", NULL))
        return sig;

    free(sig);
    return NULL;
}

static bool
verify(const char *alg, EVP_PKEY *key,
       const char *prot, const char *payl,
       const uint8_t sig[], size_t sigl)
{
    const uint8_t *k = NULL;
    uint8_t *hsh = NULL;
    bool ret = false;
    size_t hshl = 0;
    size_t kl = 0;

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return false;

    hsh = sign(alg, key, prot, payl, &hshl);
    if (!hsh)
        return false;

    uint8_t tmp[hshl];

    if (RAND_bytes(tmp, hshl) > 0) {
        memcpy(tmp, sig, sigl > hshl ? hshl : sigl);
        ret = CRYPTO_memcmp(tmp, hsh, hshl) == 0;
    }

    free(hsh);
    return ret;
}

static algo_t algo = {
    .names = (const char*[]) { NAMES, NULL },
    .type = ALGO_TYPE_SIGN,
    .generate = generate,
    .suggest = suggest,
    .verify = verify,
    .sign = sign,
};

static void __attribute__((constructor))
constructor(void)
{
    algo.next = algos;
    algos = &algo;
}
