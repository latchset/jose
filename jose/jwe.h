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
 * JSON Web Encryption (RFC 7516)
 *
 * A JSON Web Encryption (JWE) object contains (usually) two levels of
 * encryption. First, the plaintext is encrypted with a random symmetric key.
 * In José, we call this key the Content Encryption Key (CEK). Next, the CEK is
 * wrapped (encrypted) with one or more keys. These keys are standard JSON Web
 * Keys (JWK) and may be symmetric or asymmetric.
 *
 * Thus there is (usually) one CEK and one or more JWKs. However, there are
 * some exceptions to this rule. Two such examples are the algorithms: "dir"
 * and "ECDH-ES". In the first case, the JWK is a symmetric key and is used
 * directly as the CEK. In the second case, an ECDH key exchange is performed
 * and the result is used directly as the CEK. But in general, the maxim holds.
 *
 * This means that you can encrypt the data using one CEK and then encrypt the
 * CEK to multiple recipients. With this schema, multiple recipients can each
 * decrypt the data using their own key without having to send separate
 * ciphertext to each recipient.
 *
 * For maximum flexibility, José structures its API to take advantage of this
 * schema. For example, when encrypting to two recipients, the code could look
 * like this (error handling omitted):
 *
 *     json_t *enc(void *plaintext, size_t len, json_t *jwk0, json_t *jwk1) {
 *         json_auto_t *jwe = json_object();
 *         json_auto_t *cek = json_object();
 *
 *         // Wrap to the first recipient (CEK generated implicitly)
 *         jose_jwe_enc_jwk(NULL, jwe, NULL, jwk0, cek);
 *
 *         // Wrap to the second recipient
 *         jose_jwe_enc_jwk(NULL, jwe, NULL, jwk1, cek);
 *
 *         // Encrypt plaintext using the generated CEK
 *         jose_jwe_enc_cek(NULL, jwe, cek, plaintext, len);
 *
 *         return json_incref(jwe);
 *     }
 *
 * However, because José intends to be easy to use, we also provide shortcuts.
 * For example, you could use a JWKSet which contains multiple JWKs:
 *
 *     json_t *enc(void *plaintext, size_t len, json_t *jwkset) {
 *         json_auto_t *jwe = json_object();
 *
 *         // Perform wrapping and encryption to all recipients
 *         jose_jwe_enc(NULL, jwe, NULL, jwkset, plaintext, len);
 *
 *         return json_incref(jwe);
 *     }
 *
 * Here are two tips to remember. First, let José generate your CEK implicitly.
 * Second, always perform wrapping before encryption. Both of these tips are
 * important because some wrapping algorithms may impose constraints on the
 * generation of the CEK.
 *
 * To decrypt a JWE, we just reverse the process. First, we use a JWK to
 * unwrap the CEK. Then we use the CEK to decrypt the ciphertext. Here is how
 * that might look in code (again, error handling omitted):
 *
 *     void *dec(json_t *jwe, json_t *jwk, size_t *len) {
 *         json_auto_t *cek = NULL;
 *
 *         // Unwrap the CEK using our JWK
 *         cek = jose_jwe_dec_jwk(NULL, jwe, NULL, jwk);
 *
 *         // Decrypt ciphertext using the CEK
 *         return jose_jwe_dec_cek(NULL, jwe, cek, len);
 *     }
 *
 * Or, again, in simplified form:
 *
 *     void *dec(json_t *jwe, json_t *jwk, size_t *len) {
 *         return jose_jwe_dec(NULL, jwe, NULL, jwk, len);
 *     }
 *
 * If you need to forward a JWE to a new recipient, you can do this without
 * performing re-encryption. Just unwrap the CEK and then wrap the CEK again
 * using a new JWK. For example:
 *
 *     void fwd(json_t *jwe, json_t *oldjwk, json_t *newjwk) {
 *         json_auto_t *cek = NULL;
 *
 *         // Unwrap the CEK using the old JWK
 *         cek = jose_jwe_dec_jwk(NULL, jwe, NULL, oldjwk);
 *
 *         // Wrap the CEK to the new JWK
 *         jose_jwe_enc_jwk(NULL, jwe, NULL, newjwk, cek);
 *     }
 *
 * In all the above examples, parameters like which encryption algorithms to
 * use were inferred from our keys. Where such an inferrence cannot be made,
 * sensible and secure defaults were chosen automatically. If you would like
 * more control over the process, simply set parameters in the appropriate
 * objects (more on this in the function documentation). For example,
 * to enable plaintext compression, you can specify the \p zip property
 * in the JWE Protected Header:
 *
 *     json_t *enc(void *plaintext, size_t len, json_t *jwkset) {
 *         json_auto_t *jwe = json_pack("{s:{s:s}}", "protected", "zip", "DEF");
 *
 *         // Perform compressed wrapping and encryption to all recipients
 *         jose_jwe_enc(NULL, jwe, NULL, jwkset, plaintext, len);
 *
 *         return json_incref(jwe);
 *     }
 *
 * José currently supports the "alg", "enc" and "zip" header parameters, as
 * well as any algorithm-specific header parameters used by the specific
 * algorithms we implement. Other header parameters may be specified, but do
 * not effect the behavior of José's JWE implementation.
 *
 * \defgroup jose_jwe JWE
 * \see https://tools.ietf.org/html/rfc7516
 * @{
 */

#pragma once

#include "cfg.h"
#include "io.h"
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Merges the JOSE headers of a JWE object and a JWE recpient object.
 *
 * \param jwe  A JWE object.
 * \param rcp  A JWE recipient object.
 * \return     The newly allocated JOSE header.
 */
json_t *
jose_jwe_hdr(const json_t *jwe, const json_t *rcp);

/**
 * Wraps and encrypts plaintext.
 *
 * This function is a thin wrapper around the jose_jwe_enc_io() function
 * allowing the user to specify the plaintext in a single call. The ciphertext
 * output will be appended to the JWE as the "ciphertext" property.
 *
 * \see jose_jwe_enc_cek_io()
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param rcp  The JWE recipient object(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for wrapping.
 * \param pt   The plaintext.
 * \param ptl  The length of the plaintext.
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jwe_enc(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *jwk,
             const void *pt, size_t ptl);

/**
 * Wraps and encrypts plaintext using streaming.
 *
 * This function is a thin wrapper around the jose_jwe_enc_jwk() and
 * jose_jwe_enc_cek_io() functions, removing the complexity of managing the CEK.
 *
 * \see jose_jwe_enc_jwk()
 * \see jose_jwe_enc_cek_io()
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param rcp  The JWE recipient object(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for wrapping.
 * \param next The next IO object in the chain.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_jwe_enc_io(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *jwk,
                jose_io_t *next);

/**
 * Wraps a CEK with a JWK.
 *
 * The purpose of this function is to wrap (encrypt) or, in some cases, produce
 * the CEK (\p cek) from the provided JWK(s) (\p jwk). This function can be
 * used in two modes: single-JWK and multi-JWK.
 *
 * In single-JWK mode, the \p jwk parameter contains a JWK object and the
 * \p rcp parameter must contain either a JWE recipient object or NULL, in
 * which case a default empty JWE recipient object is created internally.
 *
 * Multi-JWK mode works exactly the same as single-JWK mode except that it
 * performs multiple wrappings in a single call. This mode is enabled by
 * passing either an array of JWK objects or a JWKSet as the \p jwk parameter.
 * In this mode, the \p rcp parameter contains one of the following values:
 *
 * 1. A JWE recipient object that will be used for all wrappings. In this case,
 *    a copy will be made for each wrapping and \p rcp will not be modified in
 *    any way.
 *
 * 2. An array of JWE recipient objects. Each object will be used with its
 *    corresponding JWK from \p jwk. If the arrays in \p sig and \p jwk are a
 *    different size, an error will occur.
 *
 * 3. NULL. This has the same effect as passing NULL for each separate JWK.
 *
 * In either mode, if the resulting JWE (\p jwe) would contain only a single
 * recipient, the JWE will be represented in Flattened JWE JSON Serialization
 * Syntax. Otherwise, it will be represented in General JWE JSON Serialization
 * Syntax.
 *
 * If the "alg" parameter is not specified in the JOSE Header, it will be
 * inferred from the JWK and the chosen algorithm will be added to the JWE
 * Per-Recipient Unprotected Header. Likewise, any missing, required,
 * algorithm-specific parameters will be either inferred or sensible, secure
 * defaults will be chosen and the results will be added to the JWE
 * Per-Recipient Unprotected Header.
 *
 * If the provided CEK (\p cek) does not contain key material, it will be
 * implicitly generated during the first call to jose_jwe_enc_jwk(). This
 * important feature enables the use of the "dir" and "ECDH-ES" algorithms.
 * In the case of the "dir" algorithm, the JWK is the CEK and thus the key
 * material is copied from \p jwk to \p cek. A similar situation arises with
 * the algorithm "ECDH-ES" where the result of a key exchange is used as the
 * CEK; thus, the CEK is produced during the wrapping process. This feature
 * implies that if multiple wrappings are created, only one of them may have
 * the algorithm "ECDH-ES" and it must be the first wrapping. Attempting to
 * use "ECDH-ES" with an existing CEK will result in an error.
 *
 * It is additionally possible to pass a password JSON string as key input
 * to the PBES2 family of algorithms anywhere a JWK can be used. Likewise, if
 * the "alg" JOSE Header parameter is not specified and a JSON string is used
 * in place of a JWK, the PBES2 family of algorithms will be inferred.
 *
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param rcp  The JWE recipient object(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for wrapping.
 * \param cek  The CEK to wrap (if empty, generated).
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jwe_enc_jwk(jose_cfg_t *cfg, json_t *jwe, json_t *rcp, const json_t *jwk,
                 json_t *cek);

/**
 * Encrypts plaintext with the CEK.
 *
 * This function is a thin wrapper around the jose_jwe_enc_cek_io() function
 * allowing the user to specify the plaintext in a single call. The ciphertext
 * output will be appended to the JWE as the "ciphertext" property.
 *
 * \see jose_jwe_enc_cek_io()
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param cek  The CEK object.
 * \param pt   The plaintext.
 * \param ptl  The length of the plaintext.
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jwe_enc_cek(jose_cfg_t *cfg, json_t *jwe, const json_t *cek,
                 const void *pt, size_t ptl);

/**
 * Encrypts plaintext with the CEK using streaming.
 *
 * The plaintext is provided through the returned IO object. The plaintext
 * will be encrypted and written to the \p next IO object. This IO object
 * works on binary data, so you may need to use a URL-safe Base64 decoder on
 * input and a URL-safe Base64 encoder on output, depending on your situation.
 *
 * Compressed plaintext can be implicitly enabled by specifying the "zip"
 * parameter the JWE Protected Header.
 *
 * If the JWE Protected Header is a JSON object rather than an encoded string,
 * this function will encode the JWE Protected Header to its URL-safe Base64
 * encoding as defined in RFC 7516. However, this function will never modify
 * a JWE Protected Header that is already encoded.
 *
 * If the "enc" parameter is not specified in the JWE Protected Header or the
 * JWE Shared Unprotected Header, it will be inferred from the CEK and stored
 * in either the JWE Protected Header or the JWE Shared Unprotected Header
 * (preferring the JWE Protected header if it can be modified).
 *
 * Please note that the "tag" property will only be added to the JWE when
 * \ref jose_io_t.done() returns.
 *
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param cek  The CEK object.
 * \param next The next IO object in the chain.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_jwe_enc_cek_io(jose_cfg_t *cfg, json_t *jwe, const json_t *cek,
                    jose_io_t *next);

/**
 * Unwraps and decrypts ciphertext.
 *
 * This function is a thin wrapper around the jose_jwe_dec_io() function
 * allowing the user to obtain the plaintext in a single call. The ciphertext
 * input will be obtained from the JWE "ciphertext" property.
 *
 * \see jose_jwe_dec_io()
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param rcp  The JWE recipient object(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for wrapping.
 * \param ptl  The length of the plaintext (output).
 * \return     The newly-allocated plaintext.
 */
void *
jose_jwe_dec(jose_cfg_t *cfg, const json_t *jwe, const json_t *rcp,
             const json_t *jwk, size_t *ptl);

/**
 * Unwraps and decrypts ciphertext using streaming.
 *
 * This function is a thin wrapper around the jose_jwe_dec_jwk() and
 * jose_jwe_dec_cek_io() functions, removing the complexity of managing the CEK.
 *
 * \see jose_jwe_dec_jwk()
 * \see jose_jwe_dec_cek_io()
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param rcp  The JWE recipient object(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for unwrapping.
 * \param next The next IO object in the chain.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_jwe_dec_io(jose_cfg_t *cfg, const json_t *jwe, const json_t *rcp,
                const json_t *jwk, jose_io_t *next);

/**
 * Unwraps a CEK with a JWK.
 *
 * The purpose of this function is to unwrap (decrypt) or, in some cases,
 * produce the CEK (\p cek) from the provided JWK(s) (\p jwk). This function
 * can be used in two modes: single-JWK and multi-JWK.
 *
 * In single-JWK mode, the \p jwk parameter contains a JWK object and the
 * \p rcp parameter must contain either a JWE recipient object you wish to
 * unwrap or NULL, in which case all JWE recipients will be tried.
 *
 * Multi-JWK mode works exactly the same as single-JWK mode except that it
 * attempts to unwrap with multiple JWKs in a single call. This mode is enabled
 * by passing either an array of JWK objects or a JWKSet as the \p jwk
 * parameter. In this mode, the \p rcp parameter contains one of the following
 * values:
 *
 * 1. A JWE recipient object that will be used for all attempted unwrappings.
 *
 * 2. An array of JWE recipient objects. Each object will be used with its
 *    corresponding JWK from \p jwk. If the arrays in \p sig and \p jwk are a
 *    different size, an error will occur.
 *
 * 3. NULL. This has the same effect as passing NULL for each separate JWK.
 *
 * In either mode, a CEK is returned for the first JWK that successfully
 * unwraps a CEK. Two exceptions to this rule are if the "dir" or "ECDH-ES"
 * algorithms are used. In this case, a CEK may be returned which will fail
 * during decryption since there is no way to completely validate the JWK with
 * these algorithms. Thus, we suggest placing the keys for these algorithms
 * last when unwrapping with multiple JWKs.
 *
 * If the "alg" parameter is not specified in the JOSE Header, it will be
 * inferred from the JWK. This includes using a JSON string in place of a JWK
 * for the PBES2 family of algorithms.
 *
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param rcp  The JWE recipient object(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for wrapping.
 * \return     On success, a newly-allocated CEK object. Otherwise, NULL.
 */
json_t *
jose_jwe_dec_jwk(jose_cfg_t *cfg, const json_t *jwe, const json_t *rcp,
                 const json_t *jwk);

/**
 * Decrypts ciphertext with the CEK.
 *
 * This function is a thin wrapper around the jose_jwe_dec_cek_io() function
 * allowing the user to obtain the plaintext in a single call. The ciphertext
 * input will be obtained from the JWE "ciphertext" property.
 *
 * \see jose_jwe_dec_cek_io()
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param cek  The CEK object.
 * \param ptl  The length of the plaintext (output).
 * \return     The newly-allocated plaintext.
 */
void *
jose_jwe_dec_cek(jose_cfg_t *cfg, const json_t *jwe, const json_t *cek,
                 size_t *ptl);

/**
 * Decrypts ciphertext with the CEK using streaming.
 *
 * The ciphertext is provided through the returned IO object. The ciphertext
 * will be decrypted and written to the \p next IO object. This IO object
 * works on binary data, so you may need to use a URL-safe Base64 decoder on
 * input and a URL-safe Base64 encoder on output, depending on your situation.
 *
 * Please note that validation of the ciphertext integrity protection is delayed
 * until \ref jose_io_t.done() returns. This means it is incredibly important
 * to check this return value and it is also important to be careful with the
 * plaintext emitted until this check is performed.
 *
 * Compressed plaintext will be internally decompressed if the "zip" property
 * is appropriately defined.
 *
 * If the "enc" parameter is not specified in the JWE Protected Header or the
 * JWE Shared Unprotected Header, it will be inferred from the CEK.
 *
 * Please note that the "tag" property on the JWE will only be accessed when
 * \ref jose_io_t.done() is called. So you may define it at any time on the
 * JWE object before calling \ref jose_io_t.done().
 *
 * \param cfg  The configuration context (optional).
 * \param jwe  The JWE object.
 * \param cek  The CEK object.
 * \param next The next IO object in the chain.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_jwe_dec_cek_io(jose_cfg_t *cfg, const json_t *jwe, const json_t *cek,
                    jose_io_t *next);

/** @} */
