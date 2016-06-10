/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <jansson.h>
#include <stdbool.h>

struct jose_key {
    size_t len;
    uint8_t key[];
};

/**
 * Create a new key.
 *
 * The initial contents of the memory are undefined.
 * The key is locked to prevent it being swapped to disk.
 */
struct jose_key *
jose_key_new(size_t len);

/**
 * Free a key.
 *
 * Its contents are wiped before being unlocked and freed.
 */
void
jose_key_free(struct jose_key *key);

/**
 * Create a JWK from a symmetric key.
 */
json_t *
jose_jwk_from_key(const struct jose_key *key);

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
struct jose_key *
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

/**
 * Returns a copy of the JWKSet. Includes private key material.
 *
 * If the input is an array of JWKs, it is converted to a JWKSet.
 */
json_t *
jose_jwkset_private(const json_t *jwkset);

/**
 * Returns a copy of the JWKSet. Excludes private key material.
 *
 * If the input is an array of JWKs, it is converted to a JWKSet.
 */
json_t *
jose_jwkset_public(const json_t *jwkset);

/**
 * Converts a JWS from compact format into JSON format.
 */
json_t *
jose_jws_from_compact(const char *jws);

/**
 * Creates an unsigned JWS from the given binary payload.
 */
json_t *
jose_jws_from_payload(const uint8_t pay[], size_t len);

/**
 * Creates an unsigned JWS from the given JSON payload.
 */
json_t *
jose_jws_from_payload_json(const json_t *pay);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one signature exists or if an unprotected header is found,
 * this operation will fail.
 */
char *
jose_jws_to_compact(const json_t *jws);

/**
 * Extracts the payload from a JWS in binary format.
 *
 * NOTE WELL: This function does not verify the JWS. Use an unverified JWS
 * payload at your own risk! You have been warned.
 */
uint8_t *
jose_jws_to_payload(const json_t *jws, size_t *len);

/**
 * Extracts the payload from a JWS in JSON format.
 *
 * NOTE WELL: This function does not verify the JWS. Use an unverified JWS
 * payload at your own risk! You have been warned.
 */
json_t *
jose_jws_to_payload_json(const json_t *jws);

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
