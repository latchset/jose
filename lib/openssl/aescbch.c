/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "misc.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <string.h>

#define NAMES "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#endif

static bool
mktag(const EVP_MD *md, const char *prot, const char *aad,
      const uint8_t ky[], size_t kyl,
      const uint8_t iv[], size_t ivl,
      const uint8_t ct[], size_t ctl,
      uint8_t tg[])
{
    uint8_t hsh[EVP_MD_size(md)];
    HMAC_CTX hctx = {};
    bool ret = false;
    uint64_t al = 0;

    if (HMAC_Init(&hctx, ky, kyl, md) <= 0)
        goto egress;

    al += strlen(prot);
    if (HMAC_Update(&hctx, (uint8_t *) prot, strlen(prot)) <= 0)
        goto egress;

    if (aad) {
        al++;
        if (HMAC_Update(&hctx, (uint8_t *) ".", 1) <= 0)
            goto egress;

        al += strlen(aad);
        if (HMAC_Update(&hctx, (uint8_t *) aad, strlen(aad)) <= 0)
            goto egress;
    }

    if (HMAC_Update(&hctx, iv, ivl) <= 0)
        goto egress;

    if (HMAC_Update(&hctx, ct, ctl) <= 0)
        goto egress;

    al = htobe64(al * 8);
    if (HMAC_Update(&hctx, (uint8_t *) &al, sizeof(al)) <= 0)
        goto egress;

    ret = HMAC_Final(&hctx, hsh, NULL) > 0;
    memcpy(tg, hsh, sizeof(hsh) / 2);

egress:
    HMAC_CTX_cleanup(&hctx);
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

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str2enum(alg, NAMES, NULL)) {
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
    } else if (!json_is_integer(bytes) || json_integer_value(bytes) != len)
        return false;

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops",
                    "encrypt", "decrypt");
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
    case SHA512_DIGEST_LENGTH: return "A256CBC-HS512";
    case SHA384_DIGEST_LENGTH: return "A192CBC-HS384";
    case SHA256_DIGEST_LENGTH: return "A128CBC-HS256";
    default: return NULL;
    }
}

static bool
encrypt(json_t *jwe, const json_t *cek, const char *enc,
        const char *prot, const char *aad,
        const uint8_t pt[], size_t ptl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    uint8_t *ct = NULL;
    uint8_t *ky = NULL;
    bool ret = false;
    size_t ctl = 0;
    size_t kyl = 0;
    int len;

    switch (str2enum(enc, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    uint8_t iv[EVP_CIPHER_iv_length(cph)];
    uint8_t tg[EVP_MD_size(md) / 2];

    ky = jose_b64_decode_buf_json(json_object_get(cek, "k"), &kyl);
    if (!ky)
        return NULL;

    if ((int) kyl != EVP_CIPHER_key_length(cph) * 2)
        goto egress;

    ct = malloc(ptl + EVP_CIPHER_block_size(cph) - 1);
    if (!ct)
        goto egress;

    if (RAND_bytes(iv, sizeof(iv)) <= 0)
        goto egress;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto egress;

    if (EVP_EncryptInit(ctx, cph, &ky[kyl / 2], iv) <= 0)
        goto egress;

    if (EVP_EncryptUpdate(ctx, ct, &len, pt, ptl) <= 0)
        goto egress;
    ctl = len;

    if (EVP_EncryptFinal(ctx, &ct[len], &len) <= 0)
        goto egress;
    ctl += len;

    if (!mktag(md, prot, aad, ky, kyl / 2, iv, sizeof(iv), ct, ctl, tg))
        goto egress;

    if (json_object_set_new(jwe, "iv",
                            jose_b64_encode_json(iv, sizeof(iv))) == -1)
        goto egress;

    if (json_object_set_new(jwe, "ciphertext",
                            jose_b64_encode_json(ct, ctl)) == -1)
        goto egress;

    if (json_object_set_new(jwe, "tag",
                            jose_b64_encode_json(tg, sizeof(tg))) == -1)
        goto egress;

    ret = true;

egress:
    EVP_CIPHER_CTX_free(ctx);
    clear_free(ky, kyl);
    free(ct);
    return ret;
}

static uint8_t *
decrypt(const json_t *jwe, const json_t *cek, const char *enc,
        const char *prot, const char *aad, size_t *ptl)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    uint8_t *ky = NULL;
    uint8_t *iv = NULL;
    uint8_t *ct = NULL;
    uint8_t *tg = NULL;
    uint8_t *pt = NULL;
    bool vfy = false;
    size_t kyl = 0;
    size_t ivl = 0;
    size_t ctl = 0;
    size_t tgl = 0;
    int len = 0;

    switch (str2enum(enc, NAMES, NULL)) {
    case 0: cph = EVP_aes_128_cbc(); md = EVP_sha256(); break;
    case 1: cph = EVP_aes_192_cbc(); md = EVP_sha384(); break;
    case 2: cph = EVP_aes_256_cbc(); md = EVP_sha512(); break;
    default: return NULL;
    }

    uint8_t tag[EVP_MD_size(md) / 2];

    ky = jose_b64_decode_buf_json(json_object_get(cek, "k"), &kyl);
    iv = jose_b64_decode_buf_json(json_object_get(jwe, "iv"), &ivl);
    ct = jose_b64_decode_buf_json(json_object_get(jwe, "ciphertext"), &ctl);
    tg = jose_b64_decode_buf_json(json_object_get(jwe, "tag"), &tgl);
    if (!ky || !iv || !ct || !tg)
        goto egress;

    if (kyl != (size_t) EVP_CIPHER_key_length(cph) * 2)
        goto egress;

    if (ivl != (size_t) EVP_CIPHER_iv_length(cph))
        goto egress;

    if (tgl != sizeof(tag))
        goto egress;

    pt = malloc(ctl);
    if (!pt)
        goto egress;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto egress;

    if (EVP_DecryptInit(ctx, cph, &ky[kyl / 2], iv) <= 0)
        goto egress;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctl) <= 0)
        goto egress;
    *ptl = len;

    if (EVP_DecryptFinal(ctx, &pt[len], &len) <= 0)
        goto egress;
    *ptl += len;

    vfy = mktag(md, prot, aad, ky, kyl / 2, iv, ivl, ct, ctl, tag);
    if (vfy)
        vfy = CRYPTO_memcmp(tag, tg, tgl) == 0;

egress:
    EVP_CIPHER_CTX_free(ctx);
    clear_free(ky, kyl);
    free(iv);
    free(ct);
    free(tg);
    if (!vfy)
        clear_free(pt, *ptl);
    return vfy ? pt : NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static const char *encs[] = { NAMES, NULL };

    static jose_jwk_resolver_t resolver = {
        .resolve = resolve
    };

    static jose_jwe_crypter_t crypter = {
        .encs = encs,
        .suggest = suggest,
        .encrypt = encrypt,
        .decrypt = decrypt,
    };

    jose_jwk_register_resolver(&resolver);
    jose_jwe_register_crypter(&crypter);
}
