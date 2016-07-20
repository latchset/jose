/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
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
resolve(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    json_t *bytes = NULL;
    json_t *upd = NULL;
    json_int_t len = 0;
    bool ret = false;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: len = 32; break;
    case 1: len = 48; break;
    case 2: len = 64; break;
    default: return true;
    }

    if (!kty && json_object_set_new(jwk, "kty", json_string("oct")) == -1)
        return false;
    if (kty && strcmp(kty, "oct") != 0)
        return false;

    if (!bytes && json_object_set_new(jwk, "bytes", json_integer(len)) == -1)
        return false;
    if (bytes && (!json_is_integer(bytes) || json_integer_value(bytes) < len))
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "sig", "key_ops",
                    "sign", "verify");
    if (!upd)
        return false;

    ret = json_object_update_missing(jwk, upd) == 0;
    json_decref(upd);
    return ret;
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

static bool
sign(json_t *sig, const json_t *jwk,
     const char *alg, const char *prot, const char *payl)
{
    const EVP_MD *md = NULL;
    uint8_t *ky = NULL;
    bool ret = false;
    size_t kyl = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hsh[EVP_MD_size(md)];

    ky = jose_b64_decode_json(json_object_get(jwk, "k"), &kyl);
    if (!ky || kyl < sizeof(hsh))
        goto egress;

    if (!hmac(md, ky, kyl, hsh,
              prot ? prot : "", ".",
              payl ? payl : ".", NULL))
        goto egress;

    ret = json_object_set_new(sig, "signature",
                              jose_b64_encode_json(hsh, sizeof(hsh))) == 0;

egress:
    clear_free(ky, kyl);
    return ret;
}

static bool
verify(const json_t *sig, const json_t *jwk,
       const char *alg, const char *prot, const char *payl)
{
    const EVP_MD *md = NULL;
    uint8_t *ky = NULL;
    uint8_t *sg = NULL;
    bool ret = false;
    size_t kyl = 0;
    size_t sgl = 0;

    switch (str2enum(alg, NAMES, NULL)) {
    case 0: md = EVP_sha256(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hsh[EVP_MD_size(md)];

    sg = jose_b64_decode_json(json_object_get(sig, "signature"), &sgl);
    if (!sg || sgl != sizeof(hsh))
        goto egress;

    ky = jose_b64_decode_json(json_object_get(jwk, "k"), &kyl);
    if (!ky || kyl < sizeof(hsh))
        goto egress;

    if (!hmac(md, ky, kyl, hsh,
              prot ? prot : "", ".",
              payl ? payl : ".", NULL))
        goto egress;

    ret = CRYPTO_memcmp(hsh, sg, sizeof(hsh)) == 0;

egress:
    clear_free(ky, kyl);
    free(sg);
    return ret;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *algs[] = { NAMES, NULL };

    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jws_signer_t signer = {
        .algs = algs,
        .suggest = suggest,
        .verify = verify,
        .sign = sign,
    };

    jose_jwk_register_resolver(&resolver);
    jose_jws_register_signer(&signer);
}
