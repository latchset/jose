/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <jose/buf.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Returns the length of data after decoding.
 */
size_t
jose_b64_dlen(size_t elen);

/**
 * Returns the length of data after encoding.
 */
size_t
jose_b64_elen(size_t dlen);

/**
 * Decodes the encoded C string to an allocated byte array.
 */
jose_buf_t *
jose_b64_decode(const char *enc);

/**
 * Decodes the encoded C string to a byte array.
 *
 * NOTE: The buffer MUST be at least as long as
 *       jose_b64_dlen(strlen(enc)).
 */
bool
jose_b64_decode_buf(const char *enc, uint8_t dec[]);

/**
 * Decodes the encoded JSON string to an allocated byte array.
 */
jose_buf_t *
jose_b64_decode_json(const json_t *enc);

/**
 * Decodes the encoded JSON string to a byte array.
 *
 * NOTE: The buffer MUST be at least as long as
 *       jose_b64_dlen(json_string_length(enc)).
 */
bool
jose_b64_decode_json_buf(const json_t *enc, uint8_t dec[]);

/**
 * Decodes the encoded JSON string containing a JSON serialization.
 *
 * Upon successful decoding, the serialization is deserialized.
 */
json_t *
jose_b64_decode_json_load(const json_t *enc);

/**
 * Encodes the input byte array to an allocated C string.
 */
char *
jose_b64_encode(const uint8_t dec[], size_t len);

/**
 * Encodes the input byte array to a C string.
 *
 * NOTE: The enc parameter MUST be at least as long as
 *       jose_b64_elen(len) + 1.
 */
void
jose_b64_encode_buf(const uint8_t dec[], size_t len, char enc[]);

/**
 * Encodes the input byte array to a JSON string.
 */
json_t *
jose_b64_encode_json(const uint8_t dec[], size_t len);

/**
 * Encodes the input JSON after serializing it.
 */
json_t *
jose_b64_encode_json_dump(const json_t *dec);
