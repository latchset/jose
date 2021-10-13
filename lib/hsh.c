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

#define _GNU_SOURCE
#include "misc.h"
#include "hsh.h"

#include <jose/b64.h>
#include "hooks.h"

json_t *
hsh(jose_cfg_t *cfg, const char *alg, const void *data, size_t dlen)
{
    jose_io_auto_t *hsh = NULL;
    jose_io_auto_t *enc = NULL;
    jose_io_auto_t *buf = NULL;
    char b[1024] = {};
    size_t l = sizeof(b);

    buf = jose_io_buffer(cfg, b, &l);
    enc = jose_b64_enc_io(buf);
    hsh = hsh_io(cfg, alg, enc);
    if (!buf || !enc || !hsh || !hsh->feed(hsh, data, dlen) || !hsh->done(hsh))
        return NULL;

    return json_stringn(b, l);
}

jose_io_t *
hsh_io(jose_cfg_t *cfg, const char *alg, jose_io_t *next)
{
    const jose_hook_alg_t *a = NULL;

    a = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, alg);
    if (!a)
        return NULL;

    return a->hash.hsh(a, cfg, next);
}

size_t
hsh_buf(jose_cfg_t *cfg, const char *alg,
        const void *data, size_t dlen, void *hash, size_t hlen)
{
    const jose_hook_alg_t *a = NULL;
    jose_io_auto_t *hsh = NULL;
    jose_io_auto_t *buf = NULL;

    a = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, alg);
    if (!a)
        return SIZE_MAX;

    if (!hash || hlen == 0)
        return a->hash.size;

    if (hlen < a->hash.size)
        return SIZE_MAX;

    buf = jose_io_buffer(cfg, hash, &hlen);
    hsh = a->hash.hsh(a, cfg, buf);
    if (!buf || !hsh || !hsh->feed(hsh, data, dlen) || !hsh->done(hsh))
        return SIZE_MAX;

    return hlen;
}
