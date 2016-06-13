/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include "key.h"
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <jansson.h>
#include <stdbool.h>

/**
 * Create a JWK from a symmetric key.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_from_key(const jose_key_t *key);

/**
 * Create a JWK from an elliptic curve asymmetric key.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_from_ec(const EC_KEY *key);

/**
 * Create a JWK from an RSA asymmetric key.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_from_rsa(const RSA *key);

/**
 * Create a copy of the JWK.
 *
 * Private key material will be included if and only if prv is true.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_copy(const json_t *jwk, bool prv);

/**
 * Convert a JWK to a symmetric key.
 */
jose_key_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_to_key(const json_t *jwk);

/**
 * Convert a JWK to an elliptic curve asymmetric key.
 */
EC_KEY * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_to_ec(const json_t *jwk);

/**
 * Convert a JWK to an RSA asymmetric key.
 */
RSA * __attribute__((warn_unused_result, nonnull(1)))
jose_jwk_to_rsa(const json_t *jwk);
