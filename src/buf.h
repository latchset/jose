/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    size_t len;
    uint8_t buf[];
} jose_buf_t;

/**
 * Creates a new buffer of the specified size.
 *
 * If lock is true, the buffer will be appropriately locked so that it will
 * not swap to disk.
 *
 * If buf is not NULL, len bytes from buf will be copied into the buffer.
 */
jose_buf_t * __attribute__((warn_unused_result))
jose_buf_new(size_t len, bool lock, uint8_t buf[]);

/**
 * Frees the specified key buffer.
 */
void
jose_buf_free(jose_buf_t *key);
