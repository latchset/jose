/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t len;
    uint8_t key[];
} jose_key_t;

/**
 * Creates a new key buffer of the specified size.
 *
 * The memory is appropriately locked so that it will not swap to disk.
 *
 * Free with jose_key_free().
 */
jose_key_t * __attribute__((warn_unused_result))
jose_key_new(size_t len);

/**
 * Frees the specified key buffer.
 *
 * The memory is wiped before unlocking.
 */
void
jose_key_free(jose_key_t *key);
