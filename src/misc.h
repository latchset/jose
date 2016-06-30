/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>

json_t *
compact_to_obj(const char *compact, ...);

bool
set_protected_new(json_t *obj, const char *key, json_t *val);

const char *
encode_protected(json_t *obj);

bool
add_entity(json_t *root, json_t *obj, const char *plural, ...);
