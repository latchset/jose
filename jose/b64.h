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

/**
 * \brief URL-safe Base64 Encoding & Decoding
 * \defgroup jose_b64 Base64
 * @{
 */

#pragma once

#include "io.h"
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

#define JOSE_B64_MAP "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/**
 * Decodes a URL-safe Base64 JSON string to a buffer.
 *
 * If \p o is NULL, the number of output bytes necessary is returned.
 *
 * This function will never write more than \p ol bytes. If the output buffer
 * is too small, an error will occur.
 *
 * \param i  The input URL-safe Base64 JSON string.
 * \param o  The output buffer (may be NULL).
 * \param ol The size of the output buffer.
 * \return   The number of bytes that were (or would be) written.
 *           If an error occurs, SIZE_MAX is returned.
 */
size_t
jose_b64_dec(const json_t *i, void *o, size_t ol);

/**
 * Creates a new IO object which performs URL-safe Base64 decoding.
 *
 * All data written to the returned IO object will be decoded before
 * passing it on to the next IO object in the chain.
 *
 * \param next The next IO object in the chain.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_b64_dec_io(jose_io_t *next);

/**
 * Decodes a URL-safe Base64 buffer to an output buffer.
 *
 * If \p o is NULL, the number of output bytes necessary is returned.
 *
 * This function will never write more than \p ol bytes. If the output buffer
 * is too small, an error will occur.
 *
 * \param i  The input URL-safe Base64 buffer.
 * \param il The size of the data in the input buffer.
 * \param o  The output buffer.
 * \param ol The size of the output buffer.
 * \return   The number of bytes that were (or would be) written.
 *           If an error occurs, SIZE_MAX is returned.
 */
size_t
jose_b64_dec_buf(const void *i, size_t il, void *o, size_t ol);

/**
 * Decodes a JSON string from a URL-safe Base64 JSON string.
 *
 * \param i The input URL-safe Base64 JSON string containing JSON data.
 * \return  The output JSON data.
 */
json_t *
jose_b64_dec_load(const json_t *i);

/**
 * Encodes data to a URL-safe Base64 JSON string.
 *
 * \param i  The input buffer.
 * \param il The size of the data in the input buffer.
 * \return   The decoded JSON data. If an error occurs, NULL is returned.
 */
json_t *
jose_b64_enc(const void *i, size_t il);

/**
 * Creates a new IO object which performs URL-safe Base64 encoding.
 *
 * All data written to the returned IO object will be encoded before passing
 * it on to the next IO object in the chain.
 *
 * \param next The next IO object in the chain.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_b64_enc_io(jose_io_t *next);

/**
 * Encodes data to a URL-safe Base64 buffer.
 *
 * If \p o is NULL, the number of output bytes necessary is returned.
 *
 * This function will never write more than \p ol bytes. If the output buffer
 * is too small, an error will occur.
 *
 * \param i  The input buffer.
 * \param il The size of the data in the input buffer.
 * \param o  The output URL-safe Base64 buffer.
 * \param ol The size of the output buffer.
 * \return   The number of bytes that were (or would be) written.
 *           If an error occurs, SIZE_MAX is returned.
 */
size_t
jose_b64_enc_buf(const void *i, size_t il, void *o, size_t ol);

/**
 * Encodes the input JSON as a URL-safe Base64 JSON string.
 *
 * \param i The input JSON data.
 * \return  The output URL-safe Base64 JSON string.
 */
json_t *
jose_b64_enc_dump(const json_t *i);

/** @} */
