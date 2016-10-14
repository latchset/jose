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

#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

bool
jose_jwk_generate(json_t *jwk);

bool
jose_jwk_clean(json_t *jwk);

bool
jose_jwk_allowed(const json_t *jwk, bool req, const char *op);

char *
jose_jwk_thumbprint(const json_t *jwk, const char *hash);

size_t
jose_jwk_thumbprint_len(const char *hash);

bool
jose_jwk_thumbprint_buf(const json_t *jwk, const char *hash, char enc[]);

json_t *
jose_jwk_thumbprint_json(const json_t *jwk, const char *hash);

json_t *
jose_jwk_exchange(const json_t *prv, const json_t *pub);
