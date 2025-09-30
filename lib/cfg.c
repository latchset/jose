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

#include <jose/cfg.h>
#undef jose_cfg_err

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>

struct jose_cfg {
    size_t refs;

    jose_cfg_err_t *err;
    void *misc;
};

jose_malloc_t jose_malloc = malloc;
jose_realloc_t jose_realloc = realloc;
jose_free_t jose_free = free;
jose_calloc_t jose_calloc = calloc;

static struct {
    uint64_t nmbr;
    const char *name;
} errnames[] = {
#define XX(n) { n, # n }
    XX(JOSE_CFG_ERR_JWK_INVALID),
    XX(JOSE_CFG_ERR_JWK_MISMATCH),
    XX(JOSE_CFG_ERR_JWK_DENIED),
    XX(JOSE_CFG_ERR_ALG_NOTSUP),
    XX(JOSE_CFG_ERR_ALG_NOINFER),
    XX(JOSE_CFG_ERR_JWS_INVALID),
#undef XX
    {}
};

static const char *
getname(uint64_t err)
{
    if (err < _JOSE_CFG_ERR_BASE)
        return strerror(err);

    for (size_t i = 0; errnames[i].name; i++) {
        if (errnames[i].nmbr == err)
            return errnames[i].name;
    }

    return "UNKNOWN";
}

static void
dflt_err(void *misc, const char *file, int line, uint64_t err,
         const char *fmt, va_list ap)
{
    fprintf(stderr, "%s:%d:", file, line);

    if (err != 0)
        fprintf(stderr, "%s:", getname(err));

    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

static const jose_cfg_t dflt = { .err = dflt_err };

jose_cfg_t *
jose_cfg(void)
{
    jose_cfg_t *cfg = NULL;
    cfg = jose_calloc(1, sizeof(*cfg));
    if (cfg)
        *cfg = dflt;
    return jose_cfg_incref(cfg);
}

void
jose_cfg_auto(jose_cfg_t **cfg)
{
    if (cfg)
        jose_cfg_decref(*cfg);
}

jose_cfg_t *
jose_cfg_incref(jose_cfg_t *cfg)
{
    if (cfg)
        cfg->refs++;

    return cfg;
}

void
jose_cfg_decref(jose_cfg_t *cfg)
{
    if (cfg->refs-- == 1)
        jose_free(cfg);
}

void
jose_cfg_set_err_func(jose_cfg_t *cfg, jose_cfg_err_t *err, void *misc)
{
    cfg->err = err ? err : dflt.err;
    cfg->misc = misc;
}

void *
jose_cfg_get_err_misc(jose_cfg_t *cfg)
{
    return cfg->err;
}

void
jose_cfg_err(jose_cfg_t *cfg, const char *file, int line, uint64_t err,
             const char *fmt, ...)
{
    const jose_cfg_t *c = cfg ? cfg : &dflt;
    va_list ap;

    va_start(ap, fmt);
    c->err(c->misc, file, line, err, fmt, ap);
    va_end(ap);
}

int
jose_set_alloc(jose_malloc_t pmalloc, jose_realloc_t prealloc, jose_free_t pfree, jose_calloc_t pcalloc)
{
    /* all of the allocator functions must be set */
    if (pmalloc == NULL || prealloc == NULL || pfree == NULL || pcalloc == NULL)
        return EINVAL;

    jose_malloc = pmalloc;
    jose_realloc = prealloc;
    jose_free = pfree;
    jose_calloc = pcalloc;

    /* Configure Jansson to use the same allocators as JOSE */
    json_set_alloc_funcs(jose_malloc, jose_free);

    return 0;
}

void
jose_get_alloc(jose_malloc_t *pmalloc, jose_realloc_t *prealloc, jose_free_t *pfree, jose_calloc_t *pcalloc)
{
    if (pmalloc) *pmalloc = jose_malloc;
    if (prealloc) *prealloc = jose_realloc;
    if (pfree) *pfree = jose_free;
    if (pcalloc) *pcalloc = jose_calloc;
}

void
jose_reset_alloc(void)
{
    jose_malloc = malloc;
    jose_realloc = realloc;
    jose_free = free;
    jose_calloc = calloc;
    /* Reset Jansson to use default allocators */
    json_set_alloc_funcs(malloc, free);
}