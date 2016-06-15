/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/evp.h>
#include <jansson.h>
#include <stdbool.h>

/**
 * Create a JWK from an EVP_PKEY.
 */
json_t * __attribute__((warn_unused_result))
jose_jwk_from_key(EVP_PKEY *key);

/**
 * Create a copy of the JWK.
 *
 * Private key material will be included if and only if prv is true.
 */
json_t * __attribute__((warn_unused_result))
jose_jwk_copy(const json_t *jwk, bool prv);

/**
 * Convert a JWK to an EVP_PKEY.
 *
 * NOTE WELL: RSA is vulnerable to a timing attack. OpenSSL provides
 *            countermeasures to protect against this. However, this
 *            requires that the OpenSSL PRNG is properly seeded before
 *            this function is called. You have been warned.
 */
EVP_PKEY * __attribute__((warn_unused_result))
jose_jwk_to_key(const json_t *jwk);
