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

EVP_PKEY *
jose_jwe_generate_cek(json_t *jwe);

bool __attribute__((warn_unused_result))
jose_jwe_encrypt(json_t *jwe, EVP_PKEY *cek, const uint8_t pt[], size_t ptl);

bool __attribute__((warn_unused_result))
jose_jwe_encrypt_json(json_t *jwe, EVP_PKEY *cek, const json_t *pt);

bool __attribute__((warn_unused_result))
jose_jwe_seal(json_t *jwe, EVP_PKEY *cek, EVP_PKEY *key, json_t *rcp);

bool __attribute__((warn_unused_result))
jose_jwe_seal_jwk(json_t *jwe, EVP_PKEY *cek, const json_t *jwk, json_t *rcp);

EVP_PKEY * __attribute__((warn_unused_result))
jose_jwe_unseal(const json_t *jwe, EVP_PKEY *key);

EVP_PKEY * __attribute__((warn_unused_result))
jose_jwe_unseal_jwk(const json_t *jwe, const json_t *jwk);

jose_buf_t * __attribute__((warn_unused_result))
jose_jwe_decrypt(const json_t *jwe, EVP_PKEY *cek);

json_t * __attribute__((warn_unused_result))
jose_jwe_decrypt_json(const json_t *jwe, EVP_PKEY *cek);
