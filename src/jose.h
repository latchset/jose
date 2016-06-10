/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <jansson.h>

typedef struct {
    size_t len;
    uint8_t key[];
} jose_key_t;

jose_key_t *
jose_key_new(size_t len);

void
jose_key_free(jose_key_t *key);


json_t *
jose_jwk_from_key(const jose_key_t *key);

json_t *
jose_jwk_from_ec(const EC_KEY *key, BN_CTX *ctx);

json_t *
jose_jwk_from_rsa(const RSA *key, BN_CTX *ctx);


jose_key_t *
jose_jwk_to_key(const json_t *jwk);

EC_KEY *
jose_jwk_to_ec(const json_t *jwk, BN_CTX *ctx);

RSA *
jose_jwk_to_rsa(const json_t *jwk, BN_CTX *ctx);
