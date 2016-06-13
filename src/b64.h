/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include "key.h"
#include <jansson.h>
#include <stdbool.h>

/**
 * Returns the length of data after decoding.
 */
size_t __attribute__((warn_unused_result))
jose_b64_dlen(size_t elen);

/**
 * Returns the length of data after encoding.
 */
size_t __attribute__((warn_unused_result))
jose_b64_elen(size_t dlen);

/**
 * Decodes data in the JSON string to the supplied buffer.
 *
 * NOTE: The buffer MUST be at least as long as
 *       jose_b64_dlen(json_string_length(json)).
 */
bool __attribute__((warn_unused_result, nonnull(1, 2)))
jose_b64_decode(const json_t *json, uint8_t buf[]);

/**
 * Decodes data in the JSON string to a key.
 */
jose_key_t * __attribute__((warn_unused_result, nonnull(1)))
jose_b64_decode_key(const json_t *json);

/**
 * Decodes data in the JSON string to JSON.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_b64_decode_json(const json_t *json);

/**
 * Encodes data in the supplied buffer to a JSON string.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_b64_encode(const uint8_t buf[], size_t len);

/**
 * Encodes the key to a JSON string.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_b64_encode_key(const jose_key_t *key);

/**
 * Encodes JSON to a JSON string.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_b64_encode_json(const json_t *json);
