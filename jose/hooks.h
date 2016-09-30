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

#include "jose.h"

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

typedef struct jose_jwk_exchanger {
    struct jose_jwk_exchanger *next;
    json_t *(*exchange)(const json_t *prv, const json_t *pub);
} jose_jwk_exchanger_t;

typedef struct jose_jws_signer {
    struct jose_jws_signer *next;

    const char **algs;
    const char *(*suggest)(const json_t *jwk);
    bool (*sign)(json_t *sig, const json_t *jwk,
                 const char *alg, const char *prot, const char *payl);
    bool (*verify)(const json_t *sig, const json_t *jwk,
                   const char *alg, const char *prot, const char *payl);
} jose_jws_signer_t;

typedef struct jose_jwe_crypter {
    struct jose_jwe_crypter *next;
    const char **encs;

    const char *
    (*suggest)(const json_t *jwk);

    bool
    (*encrypt)(json_t *jwe, const json_t *cek, const uint8_t pt[], size_t ptl,
               const char *enc, const char *prot, const char *aad);

    jose_buf_t *
    (*decrypt)(const json_t *jwe, const json_t *cek, const char *enc,
               const char *prot, const char *aad);
} jose_jwe_crypter_t;

typedef struct jose_jwe_wrapper {
    struct jose_jwe_wrapper *next;
    const char **algs;

    const char *
    (*suggest)(const json_t *jwk);

    bool
    (*wrap)(json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp,
            const char *alg);
    bool
    (*unwrap)(const json_t *jwe, const json_t *jwk, const json_t *rcp,
              const char *alg, json_t *cek);
} jose_jwe_wrapper_t;

typedef struct jose_jwe_zipper {
    struct jose_jwe_zipper *next;
    const char *zip;

    jose_buf_t *
    (*deflate)(const uint8_t val[], size_t len);

    jose_buf_t *
    (*inflate)(const uint8_t val[], size_t len);
} jose_jwe_zipper_t;

void
jose_jwk_register_type(jose_jwk_type_t *type);

jose_jwk_type_t *
jose_jwk_types(void);

void
jose_jwk_register_op(jose_jwk_op_t *op);

jose_jwk_op_t *
jose_jwk_ops(void);

void
jose_jwk_register_resolver(jose_jwk_resolver_t *resolver);

jose_jwk_resolver_t *
jose_jwk_resolvers(void);

void
jose_jwk_register_generator(jose_jwk_generator_t *generator);

jose_jwk_generator_t *
jose_jwk_generators(void);

void
jose_jwk_register_hasher(jose_jwk_hasher_t *hasher);

jose_jwk_hasher_t *
jose_jwk_hashers(void);

void
jose_jwk_register_exchanger(jose_jwk_exchanger_t *exchanger);

jose_jwk_exchanger_t *
jose_jwk_exchangers(void);

void
jose_jws_register_signer(jose_jws_signer_t *signer);

jose_jws_signer_t *
jose_jws_signers(void);

void
jose_jwe_register_crypter(jose_jwe_crypter_t *crypter);

jose_jwe_crypter_t *
jose_jwe_crypters(void);

void
jose_jwe_register_wrapper(jose_jwe_wrapper_t *wrapper);

jose_jwe_wrapper_t *
jose_jwe_wrappers(void);

void
jose_jwe_register_zipper(jose_jwe_zipper_t *zipper);

jose_jwe_zipper_t *
jose_jwe_zippers(void);
