/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint32_t lock : 1;
    const uint32_t size : 31;
    size_t used;
    uint8_t data[];
} jose_buf_t;

jose_buf_t * __attribute__((warn_unused_result, malloc))
jose_buf_new(uint32_t size, bool lock);

void
jose_buf_free(jose_buf_t *buf);
