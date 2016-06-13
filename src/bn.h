/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/bn.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

BIGNUM *
bn_from_buf(const uint8_t buf[], size_t len);

BIGNUM *
bn_from_json(const json_t *json);

bool
bn_to_buf(const BIGNUM *bn, uint8_t buf[], size_t len);

json_t *
bn_to_json(const BIGNUM *bn, size_t len);
