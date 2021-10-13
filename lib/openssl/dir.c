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

#include <string.h>

static const char *
alg_wrap_alg(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *enc = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &enc) == -1)
        return NULL;

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_ENCR)
            continue;

        if (strcmp(a->name, enc) == 0)
            return "dir";
    }

    return NULL;
}

static const char *
alg_wrap_enc(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwk)
{
    const char *enc = NULL;

    if (json_unpack((json_t *) jwk, "{s:s}", "alg", &enc) == -1)
        return NULL;

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_ENCR)
            continue;

        if (strcmp(a->name, enc) == 0)
            return a->name;
    }

    return NULL;
}

static bool
copy(json_t *to, const json_t *from)
{
    json_auto_t *cpy = NULL;
    cpy = json_deep_copy(from);
    return json_object_update(to, cpy) == 0;
}

static bool
alg_wrap_wrp(const jose_hook_alg_t *alg, jose_cfg_t *cfg, json_t *jwe,
             json_t *rcp, const json_t *jwk, json_t *cek)
{
    if (!json_object_get(cek, "k") && !copy(cek, jwk))
        return false;

    if (json_object_set_new(rcp, "encrypted_key", json_string("")) < 0)
        return false;

    return add_entity(jwe, rcp, "recipients", "header", "encrypted_key", NULL);
}

static bool
alg_wrap_unw(const jose_hook_alg_t *alg, jose_cfg_t *cfg, const json_t *jwe,
             const json_t *rcp, const json_t *jwk, json_t *cek)
{
    return copy(cek, jwk);
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_hook_alg_t algs[] = {
        { .kind = JOSE_HOOK_ALG_KIND_WRAP,
          .name = "dir",
          .wrap.eprm = "encrypt",
          .wrap.dprm = "decrypt",
          .wrap.alg = alg_wrap_alg,
          .wrap.enc = alg_wrap_enc,
          .wrap.wrp = alg_wrap_wrp,
          .wrap.unw = alg_wrap_unw },
        {}
    };

    for (size_t i = 0; algs[i].name; i++)
        jose_hook_alg_push(&algs[i]);
}
