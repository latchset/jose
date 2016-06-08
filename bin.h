/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <jansson.h>

struct bin {
    size_t len;
    uint8_t buf[];
};

struct bin *
bin_new(size_t size);

void
bin_free(struct bin *bin);

struct bin *
bin_from_json(const json_t *json);

json_t *
bin_to_json(const struct bin *bin);
