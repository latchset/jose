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
jose_jws_sign_pack(json_t *jws, EVP_PKEY *key, const char *fmt, ...);

bool __attribute__((warn_unused_result))
jose_jws_sign_vpack(json_t *jws, EVP_PKEY *key, const char *fmt, va_list ap);


bool __attribute__((warn_unused_result))
jose_jws_sign_jwk(json_t *jws, const json_t *jwks, const char *flags,
                  json_t *sig);

bool __attribute__((warn_unused_result))
jose_jws_sign_jwk_pack(json_t *jws, const json_t *jwks, const char *flags,
                       const char *fmt, ...);

bool __attribute__((warn_unused_result))
jose_jws_sign_jwk_vpack(json_t *jws, const json_t *jwks, const char *flags,
                        const char *fmt, va_list ap);

/**
 * Validates a JWS using the specified EVP_PKEY.
 */
bool __attribute__((warn_unused_result))
jose_jws_verify(const json_t *jws, EVP_PKEY *key);

/**
 * Validates a JWS using the specified JSON Web Key(s).
 *
 * The jwks parameter may be one of the following:
 *   1. A JSON Web Key
 *   2. A JSON Web Key Set
 *   3. An array of JSON Web Keys
 *
 * If the all parameter is true, a valid signature must exist for all keys.
 * Otherwise, if a valid signature exists for any key, verification succeeds.
 */
bool __attribute__((warn_unused_result))
jose_jws_verify_jwk(const json_t *jws, const json_t *jwks, bool all);
