/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct jose_jwe_crypter {
    struct jose_jwe_crypter *next;
    const char **encs;

    const char *
    (*suggest)(const json_t *jwk);

    bool
    (*encrypt)(json_t *jwe, const json_t *cek, const char *enc,
               const char *prot, const char *aad,
               const uint8_t pt[], size_t ptl);

    uint8_t *
    (*decrypt)(const json_t *jwe, const json_t *cek, const char *enc,
               const char *prot, const char *aad, size_t *ptl);
} jose_jwe_crypter_t;

typedef struct jose_jwe_sealer {
    struct jose_jwe_sealer *next;
    const char **algs;

    const char *
    (*suggest)(const json_t *jwk);

    bool
    (*seal)(const json_t *jwe, json_t *rcp, const json_t *jwk,
            const char *alg, const json_t *cek);
    bool
    (*unseal)(const json_t *jwe, const json_t *rcp, const json_t *jwk,
              const char *alg, json_t *cek);
} jose_jwe_sealer_t;

typedef struct jose_jwe_zipper {
    struct jose_jwe_zipper *next;
    const char *zip;

    uint8_t *
    (*deflate)(const uint8_t val[], size_t len, size_t *out);

    uint8_t *
    (*inflate)(const uint8_t val[], size_t len, size_t *out);
} jose_jwe_zipper_t;

void
jose_jwe_register_crypter(jose_jwe_crypter_t *crypter);

void
jose_jwe_register_sealer(jose_jwe_sealer_t *sealer);

void
jose_jwe_register_zipper(jose_jwe_zipper_t *zipper);

/**
 * Converts a JWE from compact format into JSON format.
 */
json_t * __attribute__((warn_unused_result))
jose_jwe_from_compact(const char *jwe);

/**
 * Converts a JWS from JSON format into compact format.
 *
 * If more than one recipient exists or if an unprotected header is found,
 * this operation will fail.
 *
 * Free with free().
 */
char * __attribute__((warn_unused_result))
jose_jwe_to_compact(const json_t *jwe);


bool __attribute__((warn_unused_result))
jose_jwe_encrypt(json_t *jwe, const json_t *cek,
                 const uint8_t pt[], size_t ptl);

bool __attribute__((warn_unused_result))
jose_jwe_encrypt_json(json_t *jwe, const json_t *cek, json_t *pt);


bool __attribute__((warn_unused_result))
jose_jwe_seal(json_t *jwe, const json_t *cek, const json_t *jwk, json_t *rcp);

json_t * __attribute__((warn_unused_result))
jose_jwe_unseal(const json_t *jwe, const json_t *jwk);


uint8_t * __attribute__((warn_unused_result))
jose_jwe_decrypt(const json_t *jwe, const json_t *cek, size_t *ptl);

json_t * __attribute__((warn_unused_result))
jose_jwe_decrypt_json(const json_t *jwe, const json_t *cek);

json_t *
jose_jwe_merge_header(const json_t *jwe, const json_t *rcp);
