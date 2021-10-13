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

struct jose_cfg {
    size_t refs;

    jose_cfg_err_t *err;
    void *misc;
};

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
    cfg = calloc(1, sizeof(*cfg));
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
        free(cfg);
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
