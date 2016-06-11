/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>

/**
 * Converts a JWS from compact format into JSON format.
 */
json_t *
jose_jws_from_compact(const char *jws);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one signature exists or if an unprotected header is found,
 * this operation will fail.
 */
char *
jose_jws_to_compact(const json_t *jws);

/**
 * Signs the payload and (optionally) the protected header.
 *
 * The jwks parameter can be either a JWK, an array of JWKs or a JWKSet. If
 * multiple keys are specified, a separate signature will be created for each
 * key. If any individual signature operation fails, the entire operation will
 * fail and the JWS object will be in an undefined state.
 *
 * If the algorithm is unspecified in either header, a default algorithm will
 * be selected based upon the specified key. In contrast, if an algorithm is
 * specified in either header which is not applicable for the key type, the
 * operation will fail. Thus, care should be taken when setting an algorithm
 * and attempting to sign with multiple keys in a single function call.
 *
 * Both the protected and unprotected headers are optional. If neither is
 * provided, a protected header will be created internally which will contain
 * at least the algorithm and the MIME type, if specified.
 *
 * If a key exists in both headers, the key and corresponding value will be
 * purged from the unprotected header.
 *
 * If a MIME type was specified during the JWS object creation, it will be
 * added to the unprotected header if the protected header is unspecified.
 * Otherwise, it will be added to the protected header.
 */
bool
jose_jws_sign(json_t *jws, const json_t *head, const json_t *prot,
              const json_t *jwks);


/**
 * Verifies a JWS using the specified keys.
 *
 * The jwks parameter can be either a JWK, an array of JWKs or a JWKSet.
 *
 * If all is true, the JWS must contain a signature for every input key.
 * Otherwise, if the JWS is signed by any key the operation succeeds.
 */
bool
jose_jws_verify(const json_t *jws, const json_t *jwks, bool all);
