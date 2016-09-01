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
jose_jwe_register_crypter(jose_jwe_crypter_t *crypter);

void
jose_jwe_register_wrapper(jose_jwe_wrapper_t *wrapper);

void
jose_jwe_register_zipper(jose_jwe_zipper_t *zipper);

/**
 * Converts a JWE from compact format into JSON format.
 */
json_t *
jose_jwe_from_compact(const char *jwe);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one recipient exists or if an unprotected header is found,
 * this operation will fail.
 *
 * Free with free().
 */
char *
jose_jwe_to_compact(const json_t *jwe);


bool
jose_jwe_encrypt(json_t *jwe, const json_t *cek,
                 const uint8_t pt[], size_t ptl);

bool
jose_jwe_encrypt_json(json_t *jwe, const json_t *cek, json_t *pt);


bool
jose_jwe_wrap(json_t *jwe, json_t *cek, const json_t *jwk, json_t *rcp);

json_t *
jose_jwe_unwrap(const json_t *jwe, const json_t *rcp, const json_t *jwk);


jose_buf_t *
jose_jwe_decrypt(const json_t *jwe, const json_t *cek);

json_t *
jose_jwe_decrypt_json(const json_t *jwe, const json_t *cek);

json_t *
jose_jwe_merge_header(const json_t *jwe, const json_t *rcp);
