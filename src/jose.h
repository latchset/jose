/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <jansson.h>

typedef struct {
    size_t len;
    uint8_t key[];
} jose_key_t;

/**
 * Create a new key.
 *
 * The initial contents of the memory are undefined.
 * The key is locked to prevent it being swapped to disk.
 */
jose_key_t *
jose_key_new(size_t len);

/**
 * Free a key.
 *
 * Its contents are wiped before being unlocked and freed.
 */
void
jose_key_free(jose_key_t *key);

/**
 * Create a JWK from a symmetric key.
 */
json_t *
jose_jwk_from_key(const jose_key_t *key);

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
jose_key_t *
jose_jwk_to_key(const json_t *jwk);

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
