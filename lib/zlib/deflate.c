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
#include <zlib.h>
#include <string.h>

static uint8_t *
comp_deflate(const uint8_t *buf, size_t len, size_t *out)
{
    uint8_t *o = NULL;
    z_stream strm = {};

    strm.next_in = (uint8_t *) buf;
    strm.avail_in = len;

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
                     MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;

    while (strm.avail_in > 0) {
        uint8_t *tmp = NULL;

        strm.avail_out = 16 * 1024; /* 16K blocks */

        tmp = realloc(o, strm.total_out + strm.avail_out);
        if (!tmp)
            goto error;

        o = tmp;
        strm.next_out = &o[strm.total_out];

        if (deflate(&strm, Z_FINISH) != Z_STREAM_END)
            goto error;
    }

    *out = strm.total_out;
    deflateEnd(&strm);
    return o;

error:
    deflateEnd(&strm);
    if (o)
        memset(o, 0, *out);
    free(o);
    return NULL;
}

static uint8_t *
comp_inflate(const uint8_t *buf, size_t len, size_t *out)
{
    uint8_t *o = NULL;
    z_stream strm = {};

    strm.next_in = (uint8_t *) buf;
    strm.avail_in = len;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK)
        return NULL;

    while (strm.avail_in > 0) {
        uint8_t *tmp = NULL;

        strm.avail_out = 16 * 1024; /* 16K blocks */

        tmp = realloc(o, strm.total_out + strm.avail_out);
        if (!tmp)
            goto error;

        o = tmp;
        strm.next_out = &o[strm.total_out];

        if (inflate(&strm, Z_FINISH) != Z_STREAM_END)
            goto error;
    }

    *out = strm.total_out;
    inflateEnd(&strm);
    return o;

error:
    inflateEnd(&strm);
    if (o)
        memset(o, 0, *out);
    free(o);
    return NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwe_zipper_t zipper = {
        .zip = "DEF",
        .deflate = comp_deflate,
        .inflate = comp_inflate
    };

    jose_jwe_register_zipper(&zipper);
}
