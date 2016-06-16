/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    const size_t len;
    uint8_t buf[];
} lbuf_t;

/* Create a new locked (mlock()) buffer. */
lbuf_t * __attribute__((warn_unused_result))
lbuf_new(size_t len);

/* Free the locked buffer. Contents are wiped before unlocking. */
void
lbuf_free(lbuf_t *key);
