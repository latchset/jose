/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>

/**
 * Returns a copy of the JWKSet. Includes private key material.
 *
 * If the input is an array of JWKs, it is converted to a JWKSet.
 */
json_t *
jose_jwkset_private(const json_t *jwkset);

/**
 * Returns a copy of the JWKSet. Excludes private key material.
 *
 * If the input is an array of JWKs, it is converted to a JWKSet.
 */
json_t *
jose_jwkset_public(const json_t *jwkset);
