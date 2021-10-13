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

#include "cfg.h"
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

json_t *
jose_openssl_jwk_from_EVP_PKEY(jose_cfg_t *cfg, EVP_PKEY *key);

json_t *
jose_openssl_jwk_from_RSA(jose_cfg_t *cfg, const RSA *key);

json_t *
jose_openssl_jwk_from_EC_KEY(jose_cfg_t *cfg, const EC_KEY *key);

json_t *
jose_openssl_jwk_from_EC_POINT(jose_cfg_t *cfg, const EC_GROUP *grp,
                               const EC_POINT *pub, const BIGNUM *prv);

EVP_PKEY *
jose_openssl_jwk_to_EVP_PKEY(jose_cfg_t *cfg, const json_t *jwk);

RSA *
jose_openssl_jwk_to_RSA(jose_cfg_t *cfg, const json_t *jwk);

EC_KEY *
jose_openssl_jwk_to_EC_KEY(jose_cfg_t *cfg, const json_t *jwk);
