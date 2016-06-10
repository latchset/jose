/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once
#include "jose.h"

BIGNUM *
json_to_bn(const json_t *json);

uint8_t *
json_to_buf(const json_t *json, size_t *len);

struct jose_key *
json_to_key(const json_t *json);

json_t *
json_from_bn(const BIGNUM *bn, size_t len);

json_t *
json_from_buf(const uint8_t buf[], size_t len);

json_t *
json_from_key(const struct jose_key *key);
