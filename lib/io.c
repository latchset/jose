/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
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

#include <jose/io.h>
#include "misc.h"
#include <string.h>

typedef struct {
    jose_io_t io;
    void **buf;
    size_t *len;
} io_malloc_t;

typedef struct {
    jose_io_t io;
    uint8_t *buf;
    size_t max;
    size_t *len;
} io_buffer_t;

typedef struct {
    jose_io_t io;
    FILE *file;
} io_file_t;

typedef struct {
    jose_io_t io;
    bool all;
    size_t nnexts;
    jose_io_t *nexts[];
} io_plex_t;

void
jose_io_auto(jose_io_t **io)
{
    if (!io || !*io)
        return;

    jose_io_decref(*io);
    *io = NULL;
}

jose_io_t *
jose_io_incref(jose_io_t *io)
{
    if (!io)
        return NULL;

    io->refs++;
    return io;
}

void
jose_io_decref(jose_io_t *io)
{
    if (!io)
        return;

    if (io->refs-- == 1)
        io->free(io);
}

static bool
malloc_feed(jose_io_t *io, const void *in, size_t len)
{
    io_malloc_t *i = containerof(io, io_malloc_t, io);
    uint8_t *tmp = NULL;

    if (len == 0)
        return true;

    tmp = realloc(*i->buf, *i->len + len);
    if (!tmp)
        return false;

    memcpy(&tmp[*i->len], in, len);
    *i->buf = tmp;
    *i->len += len;
    return true;
}

static bool
malloc_done(jose_io_t *io)
{
    return true;
}

static void
malloc_free(jose_io_t *io)
{
    io_malloc_t *i = containerof(io, io_malloc_t, io);

    if (i->buf && *i->buf && i->len) {
        zero(*i->buf, *i->len);
        free(*i->buf);
        *i->len = 0;
    }

    zero(i, sizeof(*i));
    free(i);
}

jose_io_t *
jose_io_malloc(jose_cfg_t *cfg, void **buf, size_t *len)
{
    jose_io_auto_t *io = NULL;
    io_malloc_t *i = NULL;

    if (!buf || !len)
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = malloc_feed;
    io->done = malloc_done;
    io->free = malloc_free;

    i->buf = buf;
    i->len = len;
    return jose_io_incref(io);
}

void *
jose_io_malloc_steal(void **buf)
{
    if (!buf)
        return NULL;

    void *out = *buf;
    *buf = NULL;
    return out;
}

static bool
buffer_feed(jose_io_t *io, const void *in, size_t len)
{
    io_buffer_t *i = containerof(io, io_buffer_t, io);

    if (len > i->max - *i->len)
        return false;

    memcpy(&i->buf[*i->len], in, len);
    *i->len += len;
    return true;
}

static bool
buffer_done(jose_io_t *io)
{
    return true;
}

static void
buffer_free(jose_io_t *io)
{
    io_buffer_t *i = containerof(io, io_buffer_t, io);
    zero(i, sizeof(*i));
    free(i);
}

jose_io_t *
jose_io_buffer(jose_cfg_t *cfg, void *buf, size_t *len)
{
    jose_io_auto_t *io = NULL;
    io_buffer_t *i = NULL;

    if (!buf || !len)
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = buffer_feed;
    io->done = buffer_done;
    io->free = buffer_free;

    i->buf = buf;
    i->max = *len;
    i->len = len;

    *len = 0;
    return jose_io_incref(io);
}

static bool
file_feed(jose_io_t *io, const void *in, size_t len)
{
    io_file_t *i = containerof(io, io_file_t, io);
    return fwrite(in, 1, len, i->file) == len;
}

static bool
file_done(jose_io_t *io)
{
    return true;
}

static void
file_free(jose_io_t *io)
{
    io_file_t *i = containerof(io, io_file_t, io);
    zero(i, sizeof(*i));
    free(i);
}

jose_io_t *
jose_io_file(jose_cfg_t *cfg, FILE *file)
{
    jose_io_auto_t *io = NULL;
    io_file_t *i = NULL;

    if (!file)
        return NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = file_feed;
    io->done = file_done;
    io->free = file_free;

    i->file = file;
    return jose_io_incref(&i->io);
}

static bool
plex_feed(jose_io_t *io, const void *in, size_t len)
{
    io_plex_t *i = containerof(io, io_plex_t, io);
    bool status = false;

    for (size_t j = 0; j < i->nnexts; j++) {
        bool s = false;

        if (!i->nexts[j])
            continue;

        s = i->nexts[j]->feed(i->nexts[j], in, len);
        status |= s;
        if (!s) {
            jose_io_auto(&i->nexts[j]);
            if (i->all)
                return false;
        }
    }

    return status;
}

static bool
plex_done(jose_io_t *io)
{
    io_plex_t *i = containerof(io, io_plex_t, io);
    bool status = false;

    for (size_t j = 0; j < i->nnexts; j++) {
        bool s = false;

        if (!i->nexts[j])
            continue;

        s = i->nexts[j]->done(i->nexts[j]);
        status |= s;
        if (!s) {
            jose_io_auto(&i->nexts[j]);
            if (i->all)
                return false;
        }
    }

    return status;
}

static void
plex_free(jose_io_t *io)
{
    io_plex_t *i = containerof(io, io_plex_t, io);

    for (size_t j = 0; j < i->nnexts; j++)
        jose_io_decref(i->nexts[j]);

    zero(i, sizeof(*i));
    free(i);
}

jose_io_t *
jose_io_multiplex(jose_cfg_t *cfg, jose_io_t **nexts, bool all)
{
    jose_io_auto_t *io = NULL;
    io_plex_t *i = NULL;
    size_t nnexts = 0;

    while (nexts && nexts[nnexts])
        nnexts++;

    i = calloc(1, sizeof(*i) + sizeof(jose_io_t *) * nnexts);
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = plex_feed;
    io->done = plex_done;
    io->free = plex_free;

    i->all = all;
    i->nnexts = nnexts;
    for (size_t j = 0; nexts && j < nnexts; j++)
        i->nexts[j] = jose_io_incref(nexts[j]);

    return jose_io_incref(&i->io);
}
