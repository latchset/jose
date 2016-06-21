/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <jansson.h>
#include <openssl/evp.h>

json_t *
vect_json(const char *name, const char *ext);

char *
vect_str(const char *name, const char *ext);

EVP_PKEY *
vect_cek(const char *name);
