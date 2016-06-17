/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include "buf.h"

#include <jansson.h>
#include <openssl/ossl_typ.h>

#include <stdbool.h>
#include <stdint.h>

/**
 * Converts a JWE from compact format into JSON format.
 */
json_t * __attribute__((warn_unused_result))
jose_jwe_from_compact(const char *jwe);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one recipient exists or if an unprotected header is found,
 * this operation will fail.
 *
 * Free with free().
 */
char * __attribute__((warn_unused_result))
jose_jwe_to_compact(const json_t *jwe);

/**
 * Encrypts the supplied plaintext (pt).
 *
 */
bool __attribute__((warn_unused_result))
jose_jwe_encrypt(json_t *jwe, const json_t *prot, const json_t *shrd,
                 const uint8_t pt[], size_t ptl, jose_buf_t **cek);

bool __attribute__((warn_unused_result))
jose_jwe_encrypt_json(json_t *jwe, const json_t *prot, const json_t *shrd,
                      const json_t *pt, int flags, jose_buf_t **cek);

bool __attribute__((warn_unused_result))
jose_jwe_seal(json_t *jwe, const jose_buf_t *cek, const json_t *head,
              EVP_PKEY *key);

bool __attribute__((warn_unused_result))
jose_jwe_seal_jwk(json_t *jwe, const jose_buf_t *cek, const json_t *head,
                  const json_t *jwks, const char *flags);

jose_buf_t * __attribute__((warn_unused_result))
jose_jwe_unseal(const json_t *jwe, EVP_PKEY *key);

jose_buf_t * __attribute__((warn_unused_result))
jose_jwe_unseal_jwk(const json_t *jwe, const json_t *jwks);

jose_buf_t * __attribute__((warn_unused_result))
jose_jwe_decrypt(const json_t *jwe, const jose_buf_t *cek);

json_t * __attribute__((warn_unused_result))
jose_jwe_decrypt_json(const json_t *jwe, const jose_buf_t *cek, int flags);
