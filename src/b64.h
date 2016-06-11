/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stddef.h>
#include <stdint.h>

uint8_t *
jose_b64_decode(const json_t *json, size_t *len);

json_t *
jose_b64_decode_json(const json_t *json);

json_t *
jose_b64_encode(const uint8_t buf[], size_t len);

json_t *
jose_b64_encode_json(const json_t *json);
