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

static const char *map = JOSE_B64_MAP;

static size_t
b64_dlen(size_t elen)
{
    switch (elen % JOSE_B64_ENC_BLK) {
    case 0: return elen / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK;
    case 2: return elen / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK + 1;
    case 3: return elen / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK + 2;
    default: return SIZE_MAX;
    }
}

static size_t
b64_elen(size_t dlen)
{
    switch (dlen % JOSE_B64_DEC_BLK) {
    case 0: return dlen / JOSE_B64_DEC_BLK * JOSE_B64_ENC_BLK;
    case 1: return dlen / JOSE_B64_DEC_BLK * JOSE_B64_ENC_BLK + 2;
    case 2: return dlen / JOSE_B64_DEC_BLK * JOSE_B64_ENC_BLK + 3;
    default: return SIZE_MAX;
    }
}

static void
io_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    jose_io_decref(i->next);
    zero(i, sizeof(*i));
    free(i);
}

static size_t
min(size_t a, size_t b)
{
    return a > b ? b : a;
}

static bool
dec_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    const char *enc = in;

    while (len > 0) {
        uint8_t buf[sizeof(i->eb) / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK];
        size_t dl = 0;
        size_t el = 0;

        /* Copy input into our input buffer. */
        el = min(sizeof(i->eb) - i->len, len);
        memcpy(&i->eb[i->len], enc, el);
        i->len += el;
        enc += el;
        len -= el;

        /* Perform encoding into our output buffer. */
        el = i->len - i->len % JOSE_B64_ENC_BLK;
        dl = jose_b64_dec_buf(i->eb, el, buf, sizeof(buf));
        if (dl == SIZE_MAX)
            return false;

        i->len -= el;
        memmove(i->eb, &i->eb[el], i->len);

        if (!i->next->feed(i->next, buf, dl))
            return false;
    }

    return true;
}

static bool
dec_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t buf[sizeof(i->eb) / JOSE_B64_ENC_BLK * JOSE_B64_DEC_BLK];
    size_t dl = 0;

    dl = jose_b64_dec_buf(i->eb, i->len, buf, sizeof(buf));
    if (dl == SIZE_MAX)
        return false;

    i->len = 0;
    if (!i->next->feed(i->next, buf, dl))
        return false;

    return i->next->done(i->next);
}

static bool
enc_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    const char *dec = in;

    while (len > 0) {
        uint8_t buf[sizeof(i->db) / JOSE_B64_DEC_BLK * JOSE_B64_ENC_BLK];
        size_t dl = 0;
        size_t el = 0;

        /* Copy input into our input buffer. */
        dl = min(sizeof(i->db) - i->len, len);
        memcpy(&i->db[i->len], dec, dl);
        i->len += dl;
        dec += dl;
        len -= dl;

        /* Perform encoding into our output buffer. */
        dl = i->len - i->len % JOSE_B64_DEC_BLK;
        el = jose_b64_enc_buf(i->db, dl, buf, sizeof(buf));
        if (el == SIZE_MAX)
            return false;

        i->len -= dl;
        memmove(i->db, &i->db[dl], i->len);

        if (!i->next->feed(i->next, buf, el))
            return false;
    }

    return true;
}

static bool
enc_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t buf[sizeof(i->db) / JOSE_B64_DEC_BLK * JOSE_B64_ENC_BLK];
    size_t el = 0;

    el = jose_b64_enc_buf(i->db, i->len, buf, sizeof(buf));
    if (el == SIZE_MAX)
        return false;

    i->len = 0;
    if (!i->next->feed(i->next, buf, el))
        return false;

    return i->next->done(i->next);
}

size_t
jose_b64_dec(const json_t *i, void *o, size_t ol)
{
    const char *b64 = NULL;
    size_t len = 0;

    if (json_unpack((json_t *) i, "s%", &b64, &len) < 0)
        return SIZE_MAX;

    if (!o)
        return b64_dlen(len);

    return jose_b64_dec_buf(b64, len, o, ol);
}

jose_io_t *
jose_b64_dec_io(jose_io_t *next)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = dec_feed;
    io->done = dec_done;
    io->free = io_free;

    i->next = jose_io_incref(next);
    return jose_io_incref(io);
}

size_t
jose_b64_dec_buf(const void *i, size_t il, void *o, size_t ol)
{
    const size_t len = strlen(map);
    const char *e = i;
    uint8_t *d = o;
    uint8_t rem = 0;
    size_t oo = 0;

    if (il == SIZE_MAX)
        return SIZE_MAX;

    if (!o)
        return b64_dlen(il);

    if (ol < b64_dlen(il))
        return SIZE_MAX;

    for (size_t io = 0; io < il; io++) {
        uint8_t v = 0;

        for (const char c = e[io]; v < len && c != map[v]; v++)
            continue;

        if (v >= len)
            return SIZE_MAX;

        switch (io % JOSE_B64_ENC_BLK) {
        case 0:
            if (!e[io+1] || rem > 0)
                return SIZE_MAX;

            rem = v << 2;
            break;

        case 1:
            d[oo++] = rem | (v >> 4);
            rem = v << 4;
            break;

        case 2:
            d[oo++] = rem | (v >> 2);
            rem = v << 6;
            break;

        case 3:
            d[oo++] = rem | v;
            rem = 0;
            break;
        }
    }

    return rem > 0 ? SIZE_MAX : oo;
}

json_t *
jose_b64_dec_load(const json_t *i)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;
    size_t size = 0;

    size = jose_b64_dec(i, NULL, 0);
    if (size == SIZE_MAX)
        return NULL;

    buf = calloc(1, size);
    if (!buf)
        return NULL;

    if (jose_b64_dec(i, buf, size) != size) {
        zero(buf, size);
        free(buf);
        return NULL;
    }

    out = json_loadb((char *) buf, size, JSON_DECODE_ANY, NULL);
    zero(buf, size);
    free(buf);
    return out;
}

json_t *
jose_b64_enc(const void *i, size_t il)
{
    json_t *out = NULL;
    char *enc = NULL;
    size_t elen = 0;

    elen = b64_elen(il);
    if (elen == SIZE_MAX)
        return NULL;

    enc = calloc(1, elen);
    if (!enc)
        return NULL;

    if (jose_b64_enc_buf(i, il, enc, elen) == elen)
        out = json_stringn(enc, elen);

    zero(enc, elen);
    free(enc);
    return out;
}

jose_io_t *
jose_b64_enc_io(jose_io_t *next)
{
    jose_io_auto_t *io = NULL;
    io_t *i = NULL;

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = enc_feed;
    io->done = enc_done;
    io->free = io_free;

    i->next = jose_io_incref(next);
    return jose_io_incref(io);
}

size_t
jose_b64_enc_buf(const void *i, size_t il, void *o, size_t ol)
{
    const uint8_t *ib = i;
    uint8_t rem = 0;
    size_t oo = 0;
    char *ob = o;

    if (!o)
        return b64_elen(il);

    if (ol < b64_elen(il))
        return SIZE_MAX;

    for (size_t io = 0; io < il; io++) {
        uint8_t c = ib[io];

        switch (io % 3) {
        case 0:
            ob[oo++] = map[c >> 2];
            ob[oo++] = map[rem = (c & 0b11) << 4];
            break;

        case 1:
            ob[oo-1] = map[rem | (c >> 4)];
            ob[oo++] = map[rem = (c & 0b1111) << 2];
            break;

        case 2:
            ob[oo-1] = map[rem | (c >> 6)];
            ob[oo++] = map[c & 0b111111];
            break;
        }
    }

    return oo;
}

json_t *
jose_b64_enc_dump(const json_t *i)
{
    json_t *out = NULL;
    char *buf = NULL;

    buf = json_dumps(i, JSON_COMPACT | JSON_SORT_KEYS);
    if (!buf)
        return NULL;

    out = jose_b64_enc((const uint8_t *) buf, strlen(buf));
    zero(buf, strlen(buf));
    free(buf);
    return out;
}
