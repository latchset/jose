/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>

enum jose_jws_flags {
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
};

/**
 * Converts a JWS from compact format into JSON format.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jws_from_compact(const char *jws);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one signature exists or if an unprotected header is found,
 * this operation will fail.
 *
 * Free with free().
 */
char * __attribute__((warn_unused_result, nonnull(1)))
jose_jws_to_compact(const json_t *jws);

/**
 * Signs the payload and (optionally) the protected header.
 *
 * The jws parameter should be a JWS object, with or without existing
 * signatures.
 *
 * Both the prot and head parameters are optional. These correspond to the
 * desired protected and unprotected headers, respectively.
 *
 * The jwks parameter can be either a JWK, an array of JWKs or a JWKSet. If
 * multiple keys are specified, a separate signature will be created for each
 * key. If any individual signature operation fails, the entire operation will
 * fail and the JWS object will be in an undefined state.
 *
 * The signature algorithm will be chosen according to this precedence:
 *   1. The "alg" parameter in the protected header.
 *   2. The "alg" parameter in the unprotected header.
 *   3. The "alg" parameter in the JWK.
 *   4. Automatically selected based on the type of the JWK.
 *
 * If an algorithm is specified in either header and the algorithm specified
 * is not applicable for the JWK, the operation will fail. Thus, care should
 * be taken when setting an algorithm in the header and attempting to sign
 * with multiple keys in a single function call.
 *
 * By using the flags parameter, some header attributes can be created
 * automatically. These flags will never cause an existing attribute to be
 * overridden. If a flag is specified and its corresponding header was not
 * specified, the header will be created in order to hold the attribute being
 * automatically created.
 */
bool __attribute__((warn_unused_result, nonnull(1, 4)))
jose_jws_sign(json_t *jws, const json_t *head, const json_t *prot,
              const json_t *jwks, enum jose_jws_flags flags);

/**
 * Verifies a JWS using the specified keys.
 *
 * The jwks parameter can be either a JWK, an array of JWKs or a JWKSet.
 *
 * If all is true, the JWS must contain a signature for every input key.
 * Otherwise, if the JWS is signed by any key the operation succeeds.
 */
bool __attribute__((warn_unused_result, nonnull(1, 2)))
jose_jws_verify(const json_t *jws, const json_t *jwks, bool all);
