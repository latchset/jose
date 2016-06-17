/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "buf.h"

#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

jose_buf_t *
jose_buf_new(uint32_t size, bool lock)
{
    jose_buf_t init = { lock, size, size };
    jose_buf_t *buf = NULL;

    buf = malloc(sizeof(init) + size);
    if (!buf)
        return NULL;

    if (lock && mlock(buf, sizeof(init) + size) != 0) {
        free(buf);
        return NULL;
    }

    memcpy(buf, &init, sizeof(init));
    return buf;
}

void
jose_buf_free(jose_buf_t *buf)
{
    if (!buf)
        return;

    if (buf->lock) {
        register uint32_t size = buf->size;
        memset(buf, 0, sizeof(*buf) + size);
        munlock(buf, sizeof(*buf) + size);
        size = 0;
    }

    free(buf);
}
