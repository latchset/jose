/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>

/**
 * Creates a copy of the JWKSet.
 *
 * Private key material will be included if and only if prv is true.
 *
 * If the input is an array of JWKs, it is converted to a JWKSet.
 */
json_t * __attribute__((warn_unused_result, nonnull(1)))
jose_jwkset_copy(const json_t *jwkset, bool prv);
