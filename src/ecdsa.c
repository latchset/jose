/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jws.h"
#include "conv.h"

#include <openssl/ecdsa.h>
#include <string.h>

static const char *
ecdsa_suggest(const EVP_PKEY *key)
{
    if (!key)
        return NULL;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_EC)
        return NULL;

    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key->pkey.ec))) {
    case NID_X9_62_prime256v1: return "ES256";
    case NID_secp384r1:        return "ES384";
    case NID_secp521r1:        return "ES512";
    default: return NULL;
    }
}

static buf_t *
ecdsa_sign(const EVP_PKEY *key, const char *alg, const char *data)
{
    const EC_GROUP *grp = NULL;
    ECDSA_SIG *ecdsa = NULL;
    const EVP_MD *md = NULL;
    const char *req = NULL;
    buf_t *sig = NULL;

    if (!key)
        return NULL;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_EC)
        return NULL;

    grp = EC_KEY_get0_group(key->pkey.ec);
    if (!grp)
        return NULL;

    switch (EC_GROUP_get_curve_name(grp)) {
    case NID_X9_62_prime256v1: req = "ES256"; md = EVP_sha256(); break;
    case NID_secp384r1:        req = "ES384"; md = EVP_sha384(); break;
    case NID_secp521r1:        req = "ES512"; md = EVP_sha512(); break;
    default: return NULL;
    }

    if (strcmp(alg, req) != 0)
        return NULL;

    uint8_t hsh[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
        return NULL;

    ecdsa = ECDSA_do_sign(hsh, EVP_MD_size(md), key->pkey.ec);
    if (!ecdsa)
        return NULL;

    sig = buf_new((EC_GROUP_get_degree(grp) + 7) / 8 * 2, false);
    if (!sig)
        goto error;

    if (!bn_to_buf(ecdsa->r, sig->buf, sig->len / 2))
        goto error;

    if (!bn_to_buf(ecdsa->s, &sig->buf[sig->len / 2], sig->len / 2))
        goto error;

    ECDSA_SIG_free(ecdsa);
    return sig;

error:
    ECDSA_SIG_free(ecdsa);
    buf_free(sig);
    return NULL;
}

static bool
ecdsa_verify(const EVP_PKEY *key, const char *alg, const char *data,
             const uint8_t sig[], size_t slen)
{
    const EC_GROUP *grp = NULL;
    const EVP_MD *md = NULL;
    ECDSA_SIG ecdsa = {};
    bool ret = false;
    int bytes = 0;

    if (!key)
        return false;

    if (EVP_PKEY_base_id(key) != EVP_PKEY_EC)
        return false;

    grp = EC_KEY_get0_group(key->pkey.ec);
    if (!grp)
        return false;

    bytes = (EC_GROUP_get_degree(grp) + 7) / 8;
    if ((int) slen != bytes * 2)
        return false;

    switch (EC_GROUP_get_curve_name(grp)) {
    case NID_X9_62_prime256v1: md = EVP_sha256(); break;
    case NID_secp384r1:        md = EVP_sha384(); break;
    case NID_secp521r1:        md = EVP_sha512(); break;
    default: return false;
    }

    uint8_t hsh[EVP_MD_size(md)];

    if (EVP_Digest(data, strlen(data), hsh, NULL, md, NULL) < 0)
        return false;

    ecdsa.r = bn_from_buf(sig, slen / 2);
    ecdsa.s = bn_from_buf(&sig[slen / 2], slen / 2);

    if (ecdsa.r && ecdsa.s)
        ret = ECDSA_do_verify(hsh, sizeof(hsh), &ecdsa, key->pkey.ec) == 1;

    BN_free(ecdsa.r);
    BN_free(ecdsa.s);
    return ret;
}

static jose_jws_alg_t ecdsa = {
    .priority = UINT8_MAX / 2,
    .algorithms = (const char * const []) { "ES256", "ES384", "ES512", NULL },
    .suggest = ecdsa_suggest,
    .sign = ecdsa_sign,
    .verify = ecdsa_verify
};

static void __attribute__((constructor))
constructor(void)
{
    jose_jws_alg_register(&ecdsa);
}
