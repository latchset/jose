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

void
jose_jwk_register_resolver(jose_jwk_resolver_t *resolver);

void
jose_jwk_register_generator(jose_jwk_generator_t *generator);

bool __attribute__((warn_unused_result))
jose_jwk_generate(json_t *jwk);

bool __attribute__((warn_unused_result))
jose_jwk_clean(json_t *jwk);

bool __attribute__((warn_unused_result))
jose_jwk_allowed(const json_t *jwk, const char *use, const char *op);
