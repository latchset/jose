/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../hook.h"
#include "../conv.h"

#include <openssl/ecdsa.h>

#include <string.h>

#define NAMES "ES256", "ES384", "ES512"

static size_t
setup(const char *alg, EVP_PKEY *key, const char *prot, const char *payl,
      uint8_t hsh[])
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    const char *tmp = NULL;
    unsigned int ign = 0;
    size_t ret = 0;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_EC)
        return 0;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
    case NID_X9_62_prime256v1: tmp = "ES256"; md = EVP_sha256(); break;
    case NID_secp384r1:        tmp = "ES384"; md = EVP_sha384(); break;
    case NID_secp521r1:        tmp = "ES512"; md = EVP_sha512(); break;
    default: return 0;
    }

    if (strcmp(alg, tmp) != 0)
        return 0;

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        goto egress;

    if (EVP_DigestInit(ctx, md) <= 0)
        goto egress;

    tmp = prot ? prot : "";
    if (EVP_DigestUpdate(ctx, (const uint8_t *) tmp, strlen(tmp)) <= 0)
        goto egress;

    if (EVP_DigestUpdate(ctx, (const uint8_t *) ".", 1) <= 0)
        goto egress;

    tmp = payl ? payl : "";
    if (EVP_DigestUpdate(ctx, (const uint8_t *) tmp, strlen(tmp)) <= 0)
        goto egress;

    if (EVP_DigestFinal(ctx, hsh, &ign) > 0)
        ret = EVP_MD_size(md);

egress:
    EVP_MD_CTX_destroy(ctx);
    return ret;
}

static bool
generate(json_t *jwk)
{
    const char *alg = NULL;
    const char *crv = NULL;
    const char *kty = NULL;
    const char *grp = NULL;
    json_t *upd = NULL;

    if (json_unpack(jwk, "{s?s,s?s,s?s}",
                    "kty", &kty, "alg", &alg, "crv", &crv) == -1)
        return false;

    switch (str_to_enum(alg, NAMES, NULL)) {
    case 0: grp = "P-256"; break;
    case 1: grp = "P-384"; break;
    case 2: grp = "P-521"; break;
    default: return true;
    }

    if (!kty) {
        if (json_object_set_new(jwk, "kty", json_string("EC")) == -1)
            return false;
    } else if (strcmp(kty, "EC") != 0)
        return false;

    if (!crv) {
        if (json_object_set_new(jwk, "crv", json_string(grp)) == -1)
            return false;
    } else if (strcmp(crv, grp) != 0)
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
    const char *crv = NULL;

    if (json_unpack((json_t *) jwk, "{s:s,s:s}",
                    "kty", &kty, "crv", &crv) == -1)
        return NULL;

    if (strcmp(kty, "EC") != 0)
        return NULL;

    switch (str_to_enum(crv, "P-256", "P-384", "P-521", NULL)) {
    case 0: return "HS256";
    case 1: return "HS384";
    case 2: return "HS512";
    default: return NULL;
    }
}

static uint8_t *
sign(const char *alg, EVP_PKEY *key,
     const char *prot, const char *payl, size_t *len)
{
    uint8_t hsh[EVP_MAX_MD_SIZE];
    ECDSA_SIG *ecdsa = NULL;
    uint8_t *sig = NULL;
    size_t hl = 0;

    hl = setup(alg, key, prot, payl, hsh);
    if (hl == 0)
        return NULL;

    ecdsa = ECDSA_do_sign(hsh, hl, key->pkey.ec);
    if (!ecdsa)
        goto error;

    *len = (EC_GROUP_get_degree(EC_KEY_get0_group(key->pkey.ec)) + 7) / 8 * 2;
    sig = malloc(*len);
    if (!sig)
        goto error;

    if (!bn_encode(ecdsa->r, sig, *len / 2))
        goto error;

    if (!bn_encode(ecdsa->s, &sig[*len / 2], *len / 2))
        goto error;

    ECDSA_SIG_free(ecdsa);
    return sig;

error:
    ECDSA_SIG_free(ecdsa);
    free(sig);
    return NULL;
}

static bool
verify(const char *alg, EVP_PKEY *key,
       const char *prot, const char *payl,
       const uint8_t sig[], size_t len)
{
    uint8_t hsh[EVP_MAX_MD_SIZE];
    ECDSA_SIG ecdsa = {};
    bool ret = false;
    size_t hl = 0;

    hl = setup(alg, key, prot, payl, hsh);
    if (hl == 0)
        return NULL;

    ecdsa.r = bn_decode(sig, len / 2);
    ecdsa.s = bn_decode(&sig[len / 2], len / 2);
    if (ecdsa.r && ecdsa.s)
        ret = ECDSA_do_verify(hsh, sizeof(hsh), &ecdsa, key->pkey.ec) == 1;

    BN_free(ecdsa.r);
    BN_free(ecdsa.s);
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
