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
 * JSON Web Keys (RFC 7517)
 *
 * A JSON Web Key (JWS) is a standard data format for expresing cryptographic
 * keys in JSON.
 *
 * \defgroup jose_jwk JWK
 * \see https://tools.ietf.org/html/rfc7517
 * \see https://tools.ietf.org/html/rfc7638
 * @{
 */

#pragma once

#include "cfg.h"
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Generates a new JWK.
 *
 * The JWK is generated using hints from the input in exactly the same format
 * as you would find in the output. For example, the most common way to
 * generate a key is to specify the algorithm you'd like to use the key with.
 * For example (error handling omitted):
 *
 *     json_t *gen(void) {
 *         json_auto_t *jwk = json_pack("{s:s}", "alg", "ES256");
 *         jose_jwk_gen(NULL, jwk);
 *         return json_incref(jwk);
 *     }
 *
 * This method is preferred because other metadata can be inferred from the
 * algorithm name, such as the key usage. Additionally, the algorithm metadata
 * can be used to automatically generate correct headers when creating
 * signatures (JWS) or encryptions (JWE). Thus, you should always default to
 * creating keys by their algorithm usage.
 *
 * However, should your requirements differ, you can also generate a key using
 * raw parameters (again, error handling omitted):
 *
 *     json_t *gen(void) {
 *         json_auto_t *jwk = json_pack("{s:s,s:s}", "kty", "EC", "crv", "P-256");
 *         jose_jwk_gen(NULL, jwk);
 *         return json_incref(jwk);
 *     }
 *
 *     json_t *gen(void) {
 *         json_auto_t *jwk = json_pack("{s:s,s:i}", "kty", "RSA", "bits", 2048);
 *         jose_jwk_gen(NULL, jwk);
 *         return json_incref(jwk);
 *     }
 *
 *     json_t *gen(void) {
 *         json_auto_t *jwk = json_pack("{s:s,s:i}", "kty", "oct", "bytes", 32);
 *         jose_jwk_gen(NULL, jwk);
 *         return json_incref(jwk);
 *     }
 *
 * In this case, "bits" and "bytes" will be removed from the final output.
 *
 * \see https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
 * \param cfg  The configuration context (optional).
 * \param jwk  The JWK to generate.
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jwk_gen(jose_cfg_t *cfg, json_t *jwk);

/**
 * Removes all private key material from a JWK.
 *
 * In addition, this function will remove any key operations from the
 * \p key_ops JWK property (if present) that apply only to the private key.
 *
 * This function should be used before exporting keys to third parties.
 *
 * \param cfg  The configuration context (optional).
 * \param jwk  The JWK to remove private keys from.
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jwk_pub(jose_cfg_t *cfg, json_t *jwk);

/**
 * Determines if an operation is permitted for a JWK.
 *
 * The operation to be confirmed (\p op) is always specified according to
 * the syntax of the "key_ops" JWK property, even when the "use" property
 * is defined on the JWK.
 *
 * This function has two modes of operation. If \p req is false, then JWKs
 * which do not have any key use metadata will be approved for this operation.
 * However, if \p req is true then this metadata will be required for approval.
 *
 * \param cfg  The configuration context (optional).
 * \param jwk  The JWK from which to remove private keys.
 * \param req  Whether JWK key use metadata is required or not.
 * \param op   The opperation to seek approval for.
 * \return     When the JWK is approved, true. Otherwise, false.
 */
bool
jose_jwk_prm(jose_cfg_t *cfg, const json_t *jwk, bool req, const char *op);

/**
 * Determines whether two JWKs have equal key material.
 *
 * This function considers relevant the same properties used for generation of
 * a thumbprint as defined by RFC 7638.
 *
 * \see jose_jwk_thp()
 * \see jose_jwk_thp_buf()
 * \param cfg  The configuration context (optional).
 * \param a    The first JWK to consider.
 * \param b    The second JWK to consider.
 * \return     When the two JWKs are equal, true. Otherwise, false.
 */
bool
jose_jwk_eql(jose_cfg_t *cfg, const json_t *a, const json_t *b);

/**
 * Calculates the thumbprint of a JWK as a URL-safe Base64 encoded JSON string.
 *
 * This function is a thin wrapper around jose_jwk_thp_buf().
 *
 * \see jose_jwk_thp_buf()
 * \param cfg  The configuration context (optional).
 * \param jwk  The JWK to calculate the thumbprint for.
 * \param alg  The hash algorithm to use.
 * \return     On success, a newly-allocated JSON string. Otherwise, NULL.
 */
json_t *
jose_jwk_thp(jose_cfg_t *cfg, const json_t *jwk, const char *alg);

/**
 * Calculates the thumbprint of a JWK.
 *
 * This function calculates the thumbprint of a JWK according to the method
 * defined by RFC 7638.
 *
 * If \p thp is NULL, this function returns the size of the buffer required
 * for the thumbprint output.
 *
 * \see https://tools.ietf.org/html/rfc7638
 * \param cfg  The configuration context (optional).
 * \param jwk  The JWK to calculate the thumbprint for.
 * \param alg  The hash algorithm to use.
 * \param thp  The output hash buffer.
 * \param len  The size of the output hash buffer.
 * \return     On success, the number of bytes written. Otherwise, SIZE_MAX.
 */
size_t
jose_jwk_thp_buf(jose_cfg_t *cfg, const json_t *jwk,
                 const char *alg, uint8_t *thp, size_t len);

/**
 * Perform a key exchange.
 *
 * The algorithm for the exchange is inferred from the inputs.
 *
 * The ECDH algorithm performs a standard elliptic curve multiplication such
 * that the public value of \p rem is multiplied by the private value of \p.
 *
 * The ECMR algorithm has three modes of operation. Where \p lcl has a
 * private key (the "d" property), it performs exactly like ECDH. If \p lcl
 * does not have a private key and \p rem does have a private key, elliptic
 * curve addition is performed. Otherwise, if neither \p lcl nor \p rem have a
 * private key, \p rem is subtracted from \p lcl using elliptic curve
 * subtraction. When using ECMR, be sure to validate the content of your inputs
 * to avoid triggering the incorrect operation!
 *
 * \param cfg  The configuration context (optional).
 * \param lcl  The local JWK (usually public/private key pair).
 * \param rem  The remote JWK (usually just a public key).
 * \return     On success, the JWK result of the key exchange. Otherwise, NULL.
 */
json_t *
jose_jwk_exc(jose_cfg_t *cfg, const json_t *lcl, const json_t *rem);

/** @} */
