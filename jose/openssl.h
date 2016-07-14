/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

json_t *
jose_openssl_jwk_from_EVP_PKEY(EVP_PKEY *key);

json_t *
jose_openssl_jwk_from_RSA(const RSA *key);

json_t *
jose_openssl_jwk_from_EC_KEY(const EC_KEY *key);

json_t *
jose_openssl_jwk_from_EC_POINT(const EC_GROUP *grp, const EC_POINT *pub,
                               const BIGNUM *prv);

EVP_PKEY *
jose_openssl_jwk_to_EVP_PKEY(const json_t *jwk);

RSA *
jose_openssl_jwk_to_RSA(const json_t *jwk);

EC_KEY *
jose_openssl_jwk_to_EC_KEY(const json_t *jwk);
