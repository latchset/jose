/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <jose/buf.h>
#include <stdlib.h>
#include <string.h>

#define container(ptr, type, field) \
    ((type *)((char *)(ptr) - offsetof(type, field)))

struct jose_buf_int {
    size_t ref;
    size_t alloc;
    uint64_t flags;
    jose_buf_t buf;
};

jose_buf_t *
jose_buf(size_t size, uint64_t flags)
{
    struct jose_buf_int *b = NULL;

    b = calloc(1, sizeof(*b) + size);
    if (!b)
        return NULL;

    b->ref++;
    b->alloc = size;
    b->flags = flags;
    b->buf.size = size;
    return &b->buf;
}

jose_buf_t *
jose_buf_incref(jose_buf_t *buf)
{
    struct jose_buf_int *b = NULL;

    if (!buf)
        return NULL;

    b = container(buf, struct jose_buf_int, buf);
    b->ref++;

    return buf;
}

void
jose_buf_decref(jose_buf_t *buf)
{
    struct jose_buf_int *b = NULL;

    if (!buf)
        return;

    b = container(buf, struct jose_buf_int, buf);
    if (--b->ref == 0) {
        if (b->flags & JOSE_BUF_FLAG_WIPE)
            memset(buf, 0, sizeof(*buf) + b->alloc);
        free(b);
    }
}

void
jose_buf_auto(jose_buf_t **buf)
{
    if (!buf)
        return;

    jose_buf_decref(*buf);
    *buf = NULL;
}
