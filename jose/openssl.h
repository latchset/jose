/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jose/jwk.h>
#include <openssl/evp.h>

json_t * __attribute__((warn_unused_result))
jose_openssl_jwk_from_key(EVP_PKEY *key, jose_jwk_type_t type);

EVP_PKEY * __attribute__((warn_unused_result))
jose_openssl_jwk_to_key(const json_t *jwk, jose_jwk_type_t type);
