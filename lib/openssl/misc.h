/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <jansson.h>
#include <stdbool.h>

size_t
str2enum(const char *str, ...);

BIGNUM *
bn_decode(const uint8_t buf[], size_t len);

BIGNUM *
bn_decode_json(const json_t *json);

bool
bn_encode(const BIGNUM *bn, uint8_t buf[], size_t len);

json_t *
bn_encode_json(const BIGNUM *bn, size_t len);
