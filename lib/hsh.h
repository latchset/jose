/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
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

/**
 * \brief Cryptographic Hashing
 * \defgroup hsh Hash
 * @{
 */

#pragma once

#include <jose/cfg.h>
#include <jose/io.h>
#include <jansson.h>
#include <stdint.h>

/**
 * Hashes data with the specified algorithm.
 *
 * This function hashes the first \p dlen bytes of \p data using the \p alg
 * specified and returns the output as a URL-safe Base64 encoded JSON string.
 *
 * \param cfg   The configuration context (optional).
 * \param alg   The hashing algorithm.
 * \param data  The input data buffer.
 * \param dlen  The length of the data in the input buffer.
 * \return      The hash as a URL-safe Base64 encoded JSON string.
 */
json_t *
hsh(jose_cfg_t *cfg, const char *alg, const void *data, size_t dlen);

/**
 * Hashes data with the specified algorithm using IO chaining.
 *
 * This function creates an IO chain filter that takes the data to be hashed
 * as input and outputs a hash of the input data.
 *
 * \param cfg   The configuration context (optional).
 * \param alg   The hashing algorithm.
 * \param next  The size of the output hash buffer.
 * \return      The number of bytes written to the hash buffer or SIZE_MAX on error.
 */

jose_io_t *
hsh_io(jose_cfg_t *cfg, const char *alg, jose_io_t *next);


/**
 * Hashes data with the specified algorithm into a buffer.
 *
 * This function hashes the first \p dlen bytes of \p data using the \p alg
 * specified and stores the output in \p hash (a buffer of size \p hlen).
 *
 * If \p hash is NULL, the required size of the output buffer is returned.
 *
 * \param cfg   The configuration context (optional).
 * \param alg   The hashing algorithm.
 * \param data  The input data buffer.
 * \param dlen  The length of the data in the input buffer.
 * \param hash  The output hash buffer.
 * \param hlen  The size of the output hash buffer.
 * \return      The number of bytes written to the hash buffer or SIZE_MAX on error.
 */
size_t
hsh_buf(jose_cfg_t *cfg, const char *alg,
        const void *data, size_t dlen, void *hash, size_t hlen);

/** @} */
