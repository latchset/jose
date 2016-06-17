/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"

jose_cek_t *
jose_jwe_unseal_key(const json_t *jwe, EVP_PKEY *key)
{
    return NULL;
}

jose_cek_t *
jose_jwe_unseal_jwk(const json_t *jwe, const json_t *jwks)
{
    return NULL;
}

bool
jose_jwe_decrypt(const json_t *jwe, const jose_cek_t *cek,
                 uint8_t pt[], size_t *len)
{
    return false;
}

json_t *
jose_jwe_decrypt_json(const json_t *jwe, const jose_cek_t *cek)
{
    return false;
}
