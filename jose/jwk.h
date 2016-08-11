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

typedef struct jose_jwk_type {
    struct jose_jwk_type *next;
    bool sym;
    const char *kty;
    const char **req;
    const char **prv;
} jose_jwk_type_t;

typedef struct jose_jwk_op {
    struct jose_jwk_op *next;
    const char *pub;
    const char *prv;
    const char *use;
} jose_jwk_op_t;

typedef struct jose_jwk_resolver {
    struct jose_jwk_resolver *next;
    bool (*resolve)(json_t *jwk);
} jose_jwk_resolver_t;

typedef struct jose_jwk_generator {
    struct jose_jwk_generator *next;
    const char *kty;
    bool (*generate)(json_t *jwk);
} jose_jwk_generator_t;

typedef struct jose_jwk_hasher {
    struct jose_jwk_hasher *next;
    const char *name;
    size_t size;
    bool (*hash)(const uint8_t in[], size_t inl, uint8_t out[]);
} jose_jwk_hasher_t;

void
jose_jwk_register_type(jose_jwk_type_t *type);

void
jose_jwk_register_op(jose_jwk_op_t *op);

void
jose_jwk_register_resolver(jose_jwk_resolver_t *resolver);

void
jose_jwk_register_generator(jose_jwk_generator_t *generator);

void
jose_jwk_register_hasher(jose_jwk_hasher_t *hasher);

bool
jose_jwk_generate(json_t *jwk);

bool
jose_jwk_clean(json_t *jwk);

bool
jose_jwk_allowed(const json_t *jwk, bool req, const char *use, const char *op);

char *
jose_jwk_thumbprint(const json_t *jwk, const char *hash);

size_t
jose_jwk_thumbprint_len(const char *hash);

bool
jose_jwk_thumbprint_buf(const json_t *jwk, const char *hash, char enc[]);

json_t *
jose_jwk_thumbprint_json(const json_t *jwk, const char *hash);
