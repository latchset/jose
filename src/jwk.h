/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <jansson.h>
#include <stdint.h>

/**
 * Create a JWK from a symmetric key.
 */
json_t *
jose_jwk_from_key(const uint8_t key[], size_t len);

/**
 * Create a JWK from an elliptic curve asymmetric key.
 */
json_t *
jose_jwk_from_ec(const EC_KEY *key, BN_CTX *ctx);

/**
 * Create a JWK from an RSA asymmetric key.
 */
json_t *
jose_jwk_from_rsa(const RSA *key, BN_CTX *ctx);

/**
 * Convert a JWK to a symmetric key.
 */
uint8_t *
jose_jwk_to_key(const json_t *jwk, size_t *len);

/**
 * Convert a JWK to an elliptic curve asymmetric key.
 */
EC_KEY *
jose_jwk_to_ec(const json_t *jwk, BN_CTX *ctx);

/**
 * Convert a JWK to an RSA asymmetric key.
 */
RSA *
jose_jwk_to_rsa(const json_t *jwk, BN_CTX *ctx);
