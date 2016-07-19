/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

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
jose_jwk_allowed(const json_t *jwk, const char *use, const char *op);

char *
jose_jwk_thumbprint(const json_t *jwk, const char *hash);

size_t
jose_jwk_thumbprint_len(const char *hash);

bool
jose_jwk_thumbprint_buf(const json_t *jwk, const char *hash, char enc[]);

json_t *
jose_jwk_thumbprint_json(const json_t *jwk, const char *hash);
