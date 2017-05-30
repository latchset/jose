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

#include <jose/jwe.h>
#include "../hooks.h"
#include <zlib.h>
#include <string.h>

#define containerof(ptr, type, member) \
    ((type *)((char *) ptr - offsetof(type, member)))

static size_t SIZE = 4096;

typedef struct {
    jose_io_t io;
    jose_io_t *next;
    z_stream strm;
} io_t;

static bool
feed(jose_io_t *io, const void *in, size_t len, typeof(deflate) *func)
{
    io_t *i = containerof(io, io_t, io);

    i->strm.next_in = (void *) in;
    i->strm.avail_in = len;

    while (i->strm.avail_in > 0 && i->strm.avail_out < SIZE) {
        uint8_t buf[SIZE];

        i->strm.next_out = buf;
        i->strm.avail_out = sizeof(buf);

        switch (func(&i->strm, Z_NO_FLUSH)) {
        case Z_STREAM_END: /* fallthrough */
        case Z_BUF_ERROR:  /* fallthrough */
        case Z_OK:
            if (i->next->feed(i->next, buf, SIZE - i->strm.avail_out))
                break;
            /* fallthrough */
        default:
            return false;
        }
    }

    i->strm.next_in = NULL;
    i->strm.next_out = NULL;
    i->strm.avail_out = 0;

    return i->strm.avail_in == 0;
}

static bool
done(jose_io_t *io, typeof(deflate) *func)
{
    io_t *i = containerof(io, io_t, io);

    while (i->strm.avail_out < SIZE) {
        uint8_t buf[SIZE];

        i->strm.next_out = buf;
        i->strm.avail_out = sizeof(buf);

        switch (func(&i->strm, Z_FINISH)) {
        case Z_STREAM_END: /* fallthrough */
        case Z_BUF_ERROR:  /* fallthrough */
        case Z_OK:
            if (i->next->feed(i->next, buf, SIZE - i->strm.avail_out))
                break;
            /* fallthrough */
        default:
            return false;
        }
    }

    return i->next->done(i->next);
}

static bool
def_feed(jose_io_t *io, const void *in, size_t len)
{
    return feed(io, in, len, deflate);
}

static bool
def_done(jose_io_t *io)
{
    return done(io, deflate);
}

static void
def_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    deflateEnd(&i->strm);
    free(i);
}

static bool
inf_feed(jose_io_t *io, const void *in, size_t len)
{
    return feed(io, in, len, inflate);
}

static bool
inf_done(jose_io_t *io)
{
    return done(io, inflate);
}

static void
inf_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    inflateEnd(&i->strm);
    free(i);
}

static jose_io_t *
alg_comp_def(const jose_hook_alg_t *alg, jose_cfg_t *cfg, jose_io_t *next)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = def_feed;
    io->done = def_done;
    io->free = def_free;

    i->next = jose_io_incref(next);
    if (!i->next)
        return NULL;

    if (deflateInit2(&i->strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     -MAX_WBITS, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;

    return jose_io_incref(io);
}

static jose_io_t *
alg_comp_inf(const jose_hook_alg_t *alg, jose_cfg_t *cfg, jose_io_t *next)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = inf_feed;
    io->done = inf_done;
    io->free = inf_free;

    i->next = jose_io_incref(next);
    if (!i->next)
        return NULL;

    if (inflateInit2(&i->strm, -MAX_WBITS) != Z_OK)
        return NULL;

    return jose_io_incref(io);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_alg_t alg = {
        .kind = JOSE_HOOK_ALG_KIND_COMP,
        .name = "DEF",
        .comp.def = alg_comp_def,
        .comp.inf = alg_comp_inf,
    };

    jose_hook_alg_push(&alg);
}
