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
 * JSON Web Signature (RFC 7515)
 *
 * A JSON Web Signature (JWS) is a standard data format for expresing
 * cryptographic signatures in JSON. The signatures are produced using a JSON
 * Web Key (JWK).
 *
 * For example, to create a simple signature of a string using a JWK (error
 * handling omitted):
 *
 *     json_t *sig(const char *str, const json_t *jwk) {
 *         json_auto_t *jws = json_pack("{s:o}", "payload",
 *                                      jose_b64_enc(str, strlen(str)));
 *         jose_jws_sig(NULL, jws, NULL, jwk);
 *         return json_incref(jws);
 *     }
 *
 * Likewise, to verify this signature (again, error handling omitted):
 *
 *     char *ver(const json_t *jwe, const json_t *jwk) {
 *         char *str = NULL;
 *         size_t len = 0;
 *
 *         if (!jose_jws_ver(NULL, jws, NULL, jwk))
 *             return NULL;
 *
 *         len = jose_b64_dec(json_object_get(jwe, "payload"), NULL, 0);
 *         str = calloc(1, len + 1);
 *         jose_b64_dec(json_object_get(jwe, "payload"), str, len);
 *         return str;
 *     }
 *
 * \defgroup jose_jws JWS
 * \see https://tools.ietf.org/html/rfc7515
 * @{
 */

#pragma once

#include "cfg.h"
#include "io.h"
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * Merges the JOSE headers of a JWS signature object.
 *
 * \param sig A JWS signature object.
 * \return    The newly allocated JOSE header.
 */
json_t *
jose_jws_hdr(const json_t *sig);

/**
 * Creates one or more signatures in a JWS object.
 *
 * The JWS object (\p jws) must contain the "payload" property.
 *
 * All signatures created will be appended to the JWS specified by \p jws. If
 * the resulting JWS (\p jws) would contain only a single signature, the JWS
 * will be represented in Flattened JWS JSON Serialization Syntax. Otherwise,
 * it will be represented in General JWS JSON Serialization Syntax.
 *
 * If \p jwk contains a JWK, a single signature is created. In this case, \p jws
 * must contain either a JWS signature object template or NULL. You may specify
 * algorithms or other signature behaviors simply by specifying them in the JOSE
 * headers of the JWS signature object template as defined by RFC 7515. If a
 * required property is missing, sensible defaults will be used and inserted
 * into the JOSE headers; inferring them from the JWK (\p jwk) where possible.
 *
 * If \p jwk contains an array of JWKs or a JWKSet, multiple signatures are
 * created. In this case, the \p sig parameter must contain one of the
 * following values:
 *
 * 1. A JWS signature object template that will be used for all signatures.
 *    In this case, a copy will be made for each signature and \p sig will
 *    not be modified in any way.
 *
 * 2. An array of JWS signature object templates. Each template will be
 *    used with its corresponding JWK from \p jwk. If the arrays in \p sig
 *    and \p jwk are a different size, an error will occur.
 *
 * 3. NULL. This has the same effect as passing NULL for each separate key.
 *
 * \param cfg  The configuration context (optional).
 * \param jws  The JWS object.
 * \param sig  The JWS signature object template(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for creating signatures.
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jws_sig(jose_cfg_t *cfg, json_t *jws, json_t *sig, const json_t *jwk);

/**
 * Creates one or more signatures in a JWS object using streaming.
 *
 * This function behaves substantially like jose_jws_sig() except:
 *
 * The payload is not specified in the JWS (\p jws). Rather, the payload is
 * provided using the returned IO object. The input to the returned IO object
 * will not be internally Base64 encoded. So you may need to prepend the IO
 * chain with the result of jose_b64_enc_io() (depending on your situation).
 *
 * Likewise, the payload is not stored in the JWS object (\p jws). This allows
 * for detached payloads and decreases memory use for signatures over large
 * payloads. If you would like to attach the payload, it is your responsibility
 * to do so manually.
 *
 * \param cfg  The configuration context (optional).
 * \param jws  The JWS object.
 * \param sig  The JWS signature object template(s) or NULL.
 * \param jwk  The JWK(s) or JWKSet used for creating signatures.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_jws_sig_io(jose_cfg_t *cfg, json_t *jws, json_t *sig, const json_t *jwk);


/**
 * Verifies signatures of one or more JWKs in a JWS object.
 *
 * The JWS object (\p jws) must contain the "payload" property.
 *
 * If a single JWK (\p jwk) is specified, the \p all parameter is ignored. In
 * this case, if you would like to verify a particular JWS signature object,
 * you may specify it using the \p sig parameter. Otherwise, you may simply
 * pass NULL to verify any of the JWS signature objects in the JWS object.
 *
 * If \p jwk contains an array of JWKs or a JWKSet, the \p all parameter
 * determines whether a valid signature is required for every JWK in order to
 * successfully validate the JWS. For example, if you set \p all to false this
 * function will succeed if a valid signature is found for any of the provided
 * JWKs. When using this multiple JWK signature mode, the \p sig parameter must
 * contain one of the following values:
 *
 * 1. A single JWS signature object to validate against all/any of the
 *    provided JWKs.
 *
 * 2. An array of JWS signature objects. In this case, each JWS signature
 *    object will be mapped to its corresponding JWK from \p jwk. If the
 *    arrays in \p sig and \p jwk are a different size, an error will occur.
 *
 * 3. NULL. This has the same effect as passing NULL for each separate key.
 *
 * \param cfg  The configuration context (optional).
 * \param jws  The JWS object.
 * \param sig  The JWS signature object(s) to verify or NULL.
 * \param jwk  The JWK(s) or JWKSet used for verifying signatures.
 * \param all  Whether or not to require validation of all JWKs.
 * \return     On success, true. Otherwise, false.
 */
bool
jose_jws_ver(jose_cfg_t *cfg, const json_t *jws, const json_t *sig,
             const json_t *jwk, bool all);

/**
 * Verifies signatures of one or more JWKs in a JWS object using streaming.
 *
 * This function behaves substantially like jose_jws_ver() except:
 *
 * The payload is not specified in the JWS (\p jws). Rather, the payload is
 * provided using the returned IO object. The input to the returned IO object
 * will not be internally Base64 encoded. So you may need to prepend the IO
 * chain with the result of jose_b64_enc_io() (depending on your situation).
 *
 * Final signature verification is delayed until \ref jose_io_t.done() returns.
 *
 * \param cfg  The configuration context (optional).
 * \param jws  The JWS object.
 * \param sig  The JWS signature object(s) to verify or NULL.
 * \param jwk  The JWK(s) or JWKSet used for verifying signatures.
 * \param all  Whether or not to require validation of all JWKs.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_jws_ver_io(jose_cfg_t *cfg, const json_t *jws, const json_t *sig,
                const json_t *jwk, bool all);

/** @} */
