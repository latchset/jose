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

#include "hooks.h"
#include <string.h>

static const jose_hook_jwk_t *jwks;
static const jose_hook_alg_t *algs;

void
jose_hook_jwk_push(jose_hook_jwk_t *jwk)
{
    jwk->next = jwks;
    jwks = jwk;
}

const jose_hook_jwk_t *
jose_hook_jwk_list(void)
{
    return jwks;
}

void
jose_hook_alg_push(jose_hook_alg_t *alg)
{
    alg->next = algs;
    algs = alg;
}

const jose_hook_alg_t *
jose_hook_alg_list(void)
{
    return algs;
}

const jose_hook_alg_t *
jose_hook_alg_find(jose_hook_alg_kind_t kind, const char *name)
{
    for (const jose_hook_alg_t *a = algs; a; a = a->next) {
        if (a->kind != kind)
            continue;

        if (!name || strcmp(a->name, name) == 0)
            return a;
    }

    return NULL;
}
