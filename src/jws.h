/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include "buf.h"

#include <jansson.h>
#include <openssl/evp.h>

#include <stdbool.h>

#define JOSE_JWS_ALG_VERSION 0

typedef enum {
    JOSE_JWS_FLAGS_NONE = 0,

    /** Set the algorithm used in the JWS Unprotected Header. */
    JOSE_JWS_FLAGS_ALG_HEAD = 1 << 1,

    /** Set the algorithm used in the JWS Protected Header. */
    JOSE_JWS_FLAGS_ALG_PROT = 1 << 1,

    /** Set the JWK (public attributes only) in the JWS Unprotected Header. */
    JOSE_JWS_FLAGS_JWK_HEAD = 1 << 3,

    /** Set the JWK (public attributes only) in the JWS Protected Header. */
    JOSE_JWS_FLAGS_JWK_PROT = 1 << 4,

    /** Set the JWK's kid attribute in the JWS Unprotected Header. */
    JOSE_JWS_FLAGS_KID_HEAD = 1 << 5,

    /** Set the JWK's kid attribute in the JWS Protected Header. */
    JOSE_JWS_FLAGS_KID_PROT = 1 << 6,

    JOSE_JWS_FLAGS_HEAD = JOSE_JWS_FLAGS_ALG_HEAD |
                          JOSE_JWS_FLAGS_JWK_HEAD |
                          JOSE_JWS_FLAGS_KID_HEAD,
    JOSE_JWS_FLAGS_PROT = JOSE_JWS_FLAGS_ALG_PROT |
                          JOSE_JWS_FLAGS_JWK_PROT |
                          JOSE_JWS_FLAGS_KID_PROT,
} jose_jws_flags_t;

typedef struct jose_jws_alg {
    struct jose_jws_alg *next;

    uint64_t version : 8;
    uint64_t priority : 8;

    const char * const *algorithms;

    const char *
    (*suggest)(EVP_PKEY *key);

    buf_t *
    (*sign)(EVP_PKEY *key, const char *alg, const char *data);

    bool
    (*verify)(EVP_PKEY *key, const char *alg, const char *data,
              const uint8_t sig[], size_t slen);
} jose_jws_alg_t;

void
jose_jws_alg_register(jose_jws_alg_t *alg);

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
              EVP_PKEY *key, jose_jws_flags_t flags);

bool __attribute__((warn_unused_result))
jose_jws_sign_jwk(json_t *jws, const json_t *head, const json_t *prot,
                  const json_t *jwks, jose_jws_flags_t flags);

bool __attribute__((warn_unused_result))
jose_jws_verify(const json_t *jws, EVP_PKEY *key);

bool __attribute__((warn_unused_result))
jose_jws_verify_jwk(const json_t *jws, const json_t *jwks, bool all);
