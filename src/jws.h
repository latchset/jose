/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <openssl/evp.h>

#include <stdbool.h>

/**
 * Converts a JWS from compact format into JSON format.
 */
json_t * __attribute__((warn_unused_result))
jose_jws_from_compact(const char *jws);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one signature exists or if an unprotected header is found,
 * this operation will fail.
 *
 * Free with free().
 */
char * __attribute__((warn_unused_result))
jose_jws_to_compact(const json_t *jws);

bool __attribute__((warn_unused_result))
jose_jws_sign(json_t *jws, EVP_PKEY *key, json_t *sig);

bool __attribute__((warn_unused_result))
jose_jws_sign_jwk(json_t *jws, const json_t *jwk, json_t *sig);

bool __attribute__((warn_unused_result))
jose_jws_verify(const json_t *jws, EVP_PKEY *key);

bool __attribute__((warn_unused_result))
jose_jws_verify_jwk(const json_t *jws, const json_t *jwk);
