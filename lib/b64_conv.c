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

#include <jose/b64.h>
#include "misc.h"

#include <stdbool.h>
#include <string.h>

#define JOSE_B64_DEC_BLK 3
#define JOSE_B64_ENC_BLK 4

typedef struct {
    jose_io_t io;
    jose_io_t *next;
    size_t len;
    union {
        uint8_t db[16 * JOSE_B64_DEC_BLK];
        char    eb[16 * JOSE_B64_ENC_BLK];
    };
} io_t;

static size_t
min(size_t a, size_t b)
{
    return a > b ? b : a;
}

static bool
conv_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    size_t dl = 0;
    uint8_t buf[sizeof(i->eb) / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK];
    dl = jose_b64_conv_buf(i->eb, i->len, buf, sizeof(buf));
    if (dl == SIZE_MAX)
        return false;
    i->len = 0;

    if (!i->next->feed(i->next, buf, dl))
        return false;

    return i->next->done(i->next);
}
static bool
conv_feed(jose_io_t *io, const void *in, size_t len) {
    io_t *i = containerof(io, io_t, io);
    const char* conv = in;
    while (len > 0) {
        uint8_t buf[sizeof(i->eb) / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK];
        size_t cl = 0;
        size_t el = 0;

        /* Copy el bytes into our encoded data buffer */
        el = min(sizeof(i->eb) - i->len, len);
        memcpy(&i->eb[i->len], conv, el);
        i->len += el;
        conv += el;
        len -= el;



        cl = jose_b64_conv_buf(i->eb, el, buf, sizeof(buf));
        if (cl == SIZE_MAX)
            return false;

        i->len -= el;
        memmove(i->eb, &i->eb[el], i->len);

        if (!i->next->feed(i->next, buf, cl))
            return false;

    }
    return true;
}

static size_t
b64_clen(const char* e, size_t il)
{
    size_t len = 0;
    for (size_t i = 0; i < il; i++) {
        if (e[i] == '=')
            continue;
        len++;
    }
    return len;
}

size_t
jose_b64_conv_buf(const void *i, size_t il, void *o, size_t ol)
{
    const char* e = i;
    uint8_t *d = o;
    size_t ix = 0;
    if (il == SIZE_MAX)
        return SIZE_MAX;

    if (!o)
        return b64_clen(e, il);

    if (ol < b64_clen(e, il))
        return SIZE_MAX;

    for (size_t io = 0; io < il; io++) {
        if (e[io] == '/') {
            d[ix++] = '_';
            continue;
        }
        if (e[io] == '+') {
            d[ix++] = '-';
            continue;
        }
        if (e[io] == '=')
            continue;
        d[ix++] = e[io];
    }
    return ix;
}

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    jose_io_decref(i->next);
    zero(i, sizeof(*i));
    free(i);
}

jose_io_t *
jose_b64_conv_io(jose_io_t *next)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = conv_feed;
    io->done = conv_done;
    io->free = io_free;

    i->next = jose_io_incref(next);
    return jose_io_incref(io);
}
