/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    size_t len;
    uint8_t buf[];
} buf_t;

buf_t * __attribute__((warn_unused_result))
buf_new(size_t len, bool lock);

void
buf_free(buf_t *key);
