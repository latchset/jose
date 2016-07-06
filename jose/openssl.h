/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jose/jwk.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

json_t * __attribute__((warn_unused_result))
jose_openssl_jwk_from_EVP_PKEY(EVP_PKEY *key, jose_jwk_type_t type);

json_t * __attribute__((warn_unused_result))
jose_openssl_jwk_from_RSA(const RSA *key);

json_t * __attribute__((warn_unused_result))
jose_openssl_jwk_from_EC_KEY(const EC_KEY *key);

json_t * __attribute__((warn_unused_result))
jose_openssl_jwk_from_EC_POINT(const EC_GROUP *grp, const EC_POINT *pub,
                               const BIGNUM *prv);

EVP_PKEY * __attribute__((warn_unused_result))
jose_openssl_jwk_to_EVP_PKEY(const json_t *jwk, jose_jwk_type_t type);

RSA * __attribute__((warn_unused_result))
jose_openssl_jwk_to_RSA(const json_t *jwk);

EC_KEY * __attribute__((warn_unused_result))
jose_openssl_jwk_to_EC_KEY(const json_t *jwk);
