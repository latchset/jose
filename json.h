/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once
#include "jose.h"

jose_key_t *
json_to_key(const json_t *json);

BIGNUM *
json_to_bn(const json_t *json);

json_t *
json_from_key(const jose_key_t *key);

json_t *
json_from_bn(const BIGNUM *bn, size_t len);
