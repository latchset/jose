/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include "buf.h"
#include <jansson.h>

json_t *
vect_json(const char *name, const char *ext);

jose_buf_t *
vect_buf(const char *name, const char *ext);

char *
vect_str(const char *name, const char *ext);

jose_buf_t *
vect_b64(const char *name, const char *ext);
