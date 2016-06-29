/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"
#include "../b64.h"

#include <openssl/rand.h>

#include <string.h>

#define CRYPT_NAMES "A128GCM", "A192GCM", "A256GCM"
#define SEAL_NAMES "A128GCMKW", "A192GCMKW", "A256GCMKW"

static bool
generate(json_t *jwk)
{
    const char *kty = NULL;
    const char *alg = NULL;
    const char *opa = NULL;
    const char *opb = NULL;
    json_t *bytes = NULL;
    json_t *upd = NULL;
    json_int_t len = 0;

    if (json_unpack(jwk, "{s?s,s?s,s?o}",
                    "kty", &kty, "alg", &alg, "bytes", &bytes) == -1)
        return false;

    switch (str_to_enum(alg, CRYPT_NAMES, SEAL_NAMES, NULL)) {
    case 0: len = 16; opa = "encrypt"; opb = "decrypt"; break;
    case 1: len = 24; opa = "encrypt"; opb = "decrypt"; break;
    case 2: len = 32; opa = "encrypt"; opb = "decrypt"; break;
    case 3: len = 16; opa = "wrapKey"; opb = "unwrapKey"; break;
    case 4: len = 24; opa = "wrapKey"; opb = "unwrapKey"; break;
    case 5: len = 32; opa = "wrapKey"; opb = "unwrapKey"; break;
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

    upd = json_pack("{s:s,s:[s,s]}", "use", "enc", "key_ops", opa, opb);
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
suggest_crypt(const json_t *jwk)
{
    const char *kty = NULL;
    const char *k = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    switch (jose_b64_dlen(strlen(k))) {
    case 16: return "A128GCM";
    case 24: return "A192GCM";
    case 32: return "A256GCM";
    default: return NULL;
    }
}

static const char *
suggest_seal(const json_t *jwk)
{
    const char *kty = NULL;
    const char *k = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}", "kty", &kty, "k", &k) == -1)
        return NULL;

    if (strcmp(kty, "oct") != 0)
        return NULL;

    switch (jose_b64_dlen(strlen(k))) {
    case 16: return "A128GCMKW";
    case 24: return "A192GCMKW";
    case 32: return "A256GCMKW";
    default: return NULL;
    }
}

static uint8_t *
encrypt(const char *alg, EVP_PKEY *key,
        const uint8_t pt[], size_t ptl,
        size_t *ivl, size_t *ctl, size_t *tgl, ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *k = NULL;
    uint8_t *ivcttag = NULL;
    size_t kl = 0;
    va_list ap;
    int len;

    switch (str_to_enum(alg, CRYPT_NAMES, NULL)) {
    case 0: cph = EVP_aes_128_gcm(); break;
    case 1: cph = EVP_aes_192_gcm(); break;
    case 2: cph = EVP_aes_256_gcm(); break;
    default: return NULL;
    }

    k = EVP_PKEY_get0_hmac(key, &kl);
    if (!k)
        return NULL;

    if ((int) kl != EVP_CIPHER_key_length(cph))
        return NULL;

    *tgl = 16;
    *ivl = EVP_CIPHER_iv_length(cph);
    ivcttag = malloc(*ivl + *tgl + ptl + EVP_CIPHER_block_size(cph) - 1);
    if (!ivcttag)
        return NULL;

    if (RAND_bytes(ivcttag, *ivl) <= 0)
        goto error;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_EncryptInit(ctx, cph, NULL, NULL) <= 0)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, *ivl, NULL) <= 0)
        goto error;

    if (EVP_EncryptInit(ctx, NULL, k, ivcttag) <= 0)
        goto error;

    va_start(ap, tgl);
    for (const char *aad; (aad = va_arg(ap, const char *)); ) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, (uint8_t *) aad,
                              strlen(aad)) <= 0) {
            va_end(ap);
            goto error;
        }
    }
    va_end(ap);

    if (EVP_EncryptUpdate(ctx, &ivcttag[*ivl], &len, pt, ptl) <= 0)
        goto error;
    *ctl = len;

    if (EVP_EncryptFinal(ctx, &ivcttag[*ivl + len], &len) <= 0)
        goto error;
    *ctl += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tgl,
                            &ivcttag[*ivl + *ctl]) <= 0)
        goto error;

    EVP_CIPHER_CTX_free(ctx);
    return ivcttag;

error:
    EVP_CIPHER_CTX_free(ctx);
    free(ivcttag);
    return NULL;
}

static uint8_t *
decrypt(const char *alg, EVP_PKEY *key,
        const uint8_t iv[], size_t ivl,
        const uint8_t ct[], size_t ctl,
        const uint8_t tg[], size_t tgl,
        size_t *ptl, ...)
{
    const EVP_CIPHER *cph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const uint8_t *ky = NULL;
    uint8_t *pt = NULL;
    size_t kyl = 0;
    int len = 0;
    va_list ap;

    ky = EVP_PKEY_get0_hmac(key, &kyl);
    if (!ky)
        return NULL;

    switch (str_to_enum(alg, CRYPT_NAMES, NULL)) {
    case 0: cph = EVP_aes_128_gcm(); break;
    case 1: cph = EVP_aes_192_gcm(); break;
    case 2: cph = EVP_aes_256_gcm(); break;
    default: return NULL;
    }

    uint8_t sk[EVP_CIPHER_key_length(cph)];
    uint8_t si[EVP_CIPHER_iv_length(cph)];
    uint8_t st[16];

    if (RAND_bytes(sk, sizeof(sk)) <= 0)
        return NULL;
    if (RAND_bytes(st, sizeof(st)) <= 0)
        return NULL;
    if (RAND_bytes(si, sizeof(si)) <= 0)
        return NULL;

    memcpy(sk, ky, kyl > sizeof(sk) ? sizeof(sk) : kyl);
    memcpy(st, tg, tgl > sizeof(st) ? sizeof(st) : tgl);
    memcpy(si, iv, ivl > sizeof(si) ? sizeof(si) : ivl);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto error;

    if (EVP_DecryptInit(ctx, cph, sk, si) <= 0)
        goto error;

    va_start(ap, ptl);
    for (const char *aad; (aad = va_arg(ap, const char *)); ) {
        if (EVP_DecryptUpdate(ctx, NULL, &len,
                              (uint8_t *) aad, strlen(aad)) <= 0) {
            va_end(ap);
            goto error;
        }
    }
    va_end(ap);

    pt = malloc(ctl);
    if (!pt)
        goto error;

    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctl) <= 0)
        goto error;
    *ptl = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(st), st) <= 0)
        goto error;

    if (EVP_DecryptFinal(ctx, &pt[len], &len) <= 0)
        goto error;
    *ptl += len;

    EVP_CIPHER_CTX_free(ctx);
    return pt;

error:
    EVP_CIPHER_CTX_free(ctx);
    memset(pt, 0, ctl);
    free(pt);
    return NULL;
}

static uint8_t *
seal(const char *alg, EVP_PKEY *key,
     const uint8_t pt[], size_t ptl,
     size_t *ivl, size_t *ctl, size_t *tgl)
{
    const uint8_t *ky = NULL;
    size_t kyl = 0;

    ky = EVP_PKEY_get0_hmac(key, &kyl);
    if (!ky)
        return NULL;

    switch (str_to_enum(alg, SEAL_NAMES, NULL)) {
    case 0: alg = "A128GCM"; break;
    case 1: alg = "A192GCM"; break;
    case 2: alg = "A256GCM"; break;
    default: return NULL;
    }

    return encrypt(alg, key, pt, ptl, ivl, ctl, tgl, NULL);
}

static uint8_t *
unseal(const char *alg, EVP_PKEY *key,
       const uint8_t iv[], size_t ivl,
       const uint8_t ct[], size_t ctl,
       const uint8_t tg[], size_t tgl,
       size_t *ptl)
{
    switch (str_to_enum(alg, SEAL_NAMES, NULL)) {
    case 0: alg = "A128GCM"; break;
    case 1: alg = "A192GCM"; break;
    case 2: alg = "A256GCM"; break;
    default: return NULL;
    }

    return decrypt(alg, key, iv, ivl, ct, ctl, tg, tgl, ptl, NULL);
}

static algo_t algo[] = {
    { .names = (const char*[]) { CRYPT_NAMES, NULL },
      .type = ALGO_TYPE_CRYPT,
      .suggest = suggest_crypt,
      .generate = generate,
      .encrypt = encrypt,
      .decrypt = decrypt },
    { .names = (const char*[]) { SEAL_NAMES, NULL },
      .type = ALGO_TYPE_SEAL,
      .suggest = suggest_seal,
      .generate = generate,
      .unseal = unseal,
      .seal = seal },
};

static void __attribute__((constructor))
constructor(void)
{
    algo[0].next = algos;
    algos = &algo[0];

    algo[1].next = algos;
    algos = &algo[1];
}
