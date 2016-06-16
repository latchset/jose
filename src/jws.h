/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <openssl/evp.h>

#include <stdbool.h>

typedef enum {
    JOSE_JWS_FLAGS_NONE = 0,

    /** Set the JWK (public attributes only) in the JWS Unprotected Header. */
    JOSE_JWS_FLAGS_JWK_HEAD = 1 << 0,

    /** Set the JWK (public attributes only) in the JWS Protected Header. */
    JOSE_JWS_FLAGS_JWK_PROT = 1 << 1,

    /** Set the JWK's kid attribute in the JWS Unprotected Header. */
    JOSE_JWS_FLAGS_KID_HEAD = 1 << 2,

    /** Set the JWK's kid attribute in the JWS Protected Header. */
    JOSE_JWS_FLAGS_KID_PROT = 1 << 3,
} jose_jws_flags_t;

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
jose_jws_sign(json_t *jws, const json_t *head, const json_t *prot,
              EVP_PKEY *key);

bool __attribute__((warn_unused_result))
jose_jws_sign_jwk(json_t *jws, const json_t *head, const json_t *prot,
                  const json_t *jwks, jose_jws_flags_t flags);

bool __attribute__((warn_unused_result))
jose_jws_verify(const json_t *jws, EVP_PKEY *key);

bool __attribute__((warn_unused_result))
jose_jws_verify_jwk(const json_t *jws, const json_t *jwks, bool all);
