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

#include "misc.h"
#include "../hooks.h"

typedef struct {
    jose_io_t io;

    jose_io_t *next;
    EVP_MD_CTX *emc;
} io_t;

static bool
hsh_feed(jose_io_t *io, const void *in, size_t len)
{
    io_t *i = containerof(io, io_t, io);
    return EVP_DigestUpdate(i->emc, in, len) > 0;
}

static bool
hsh_done(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    uint8_t hsh[EVP_MD_CTX_size(i->emc)];
    unsigned int l = 0;

    if (EVP_DigestFinal(i->emc, hsh, &l) <= 0)
        return SIZE_MAX;

    if (!i->next->feed(i->next, hsh, l) || !i->next->done(i->next))
        return SIZE_MAX;

    return l;
}

static void
hsh_free(jose_io_t *io)
{
    io_t *i = containerof(io, io_t, io);
    jose_io_decref(i->next);
    EVP_MD_CTX_free(i->emc);
    free(i);
}

static jose_io_t *
hsh(const jose_hook_alg_t *alg, jose_cfg_t *cfg, jose_io_t *next)
{
    jose_io_auto_t *io = NULL;
    const EVP_MD *md = NULL;
    io_t *i = NULL;

    switch (str2enum(alg->name, "S512", "S384", "S256", "S224", "S1", NULL)) {
    case 0: md = EVP_sha512(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha256(); break;
    case 3: md = EVP_sha224(); break;
    case 4: md = EVP_sha1();   break;
    }

    i = calloc(1, sizeof(*i));
    if (!i)
        return NULL;

    io = jose_io_incref(&i->io);
    io->feed = hsh_feed;
    io->done = hsh_done;
    io->free = hsh_free;

    i->next = jose_io_incref(next);
    i->emc = EVP_MD_CTX_new();
    if (!i->next || !i->emc)
        return NULL;

    if (EVP_DigestInit(i->emc, md) <= 0)
        return NULL;

    return jose_io_incref(io);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_HASH, .name = "S512",
          .hash.size = 64, .hash.hsh = hsh },
        { .kind = JOSE_HOOK_ALG_KIND_HASH, .name = "S384",
          .hash.size = 48, .hash.hsh = hsh },
        { .kind = JOSE_HOOK_ALG_KIND_HASH, .name = "S256",
          .hash.size = 32, .hash.hsh = hsh },
        { .kind = JOSE_HOOK_ALG_KIND_HASH, .name = "S224",
          .hash.size = 28, .hash.hsh = hsh },
        { .kind = JOSE_HOOK_ALG_KIND_HASH, .name = "S1",
          .hash.size = 20, .hash.hsh = hsh },
        {}
    };

    for (size_t i = 0; algs[i].name; i++)
        jose_hook_alg_push(&algs[i]);
}
