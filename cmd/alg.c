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

#include "jose.h"
#include "../lib/hooks.h"
#include <string.h>

#define SUMMARY "Lists all supported algorithms"

typedef struct {
    json_t *kinds;
} jcmd_opt_t;

static const char *prefix = "jose alg [-k KIND]\n\n" SUMMARY;

static const struct {
    const char *name;
    jose_hook_alg_kind_t kind;
} kinds[] = {
    { "hash", JOSE_HOOK_ALG_KIND_HASH },
    { "sign", JOSE_HOOK_ALG_KIND_SIGN },
    { "wrap", JOSE_HOOK_ALG_KIND_WRAP },
    { "encr", JOSE_HOOK_ALG_KIND_ENCR },
    { "comp", JOSE_HOOK_ALG_KIND_COMP },
    { "exch", JOSE_HOOK_ALG_KIND_EXCH },
    {}
};

static jose_hook_alg_kind_t
name2kind(const char *name)
{
    for (size_t i = 0; name && kinds[i].name; i++) {
        if (strcmp(name, kinds[i].name) == 0)
            return kinds[i].kind;
    }

    return JOSE_HOOK_ALG_KIND_NONE;
}

static bool
opt_set_kind(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_t **all = vopt;

    if (!*all)
        *all = json_array();

    if (strcmp(arg, "?") == 0) {
        for (size_t i = 0; kinds[i].name; i++)
            fprintf(stdout, "%s\n", kinds[i].name);

        exit(EXIT_SUCCESS);
    }

    if (name2kind(arg) == JOSE_HOOK_ALG_KIND_NONE)
        return false;

    return json_array_append_new(*all, json_string(arg)) >= 0;
}

static const jcmd_doc_t doc_kind[] = {
    { .arg = "KIND", .doc = "Restrict algorithm list to a certain kind" },
    { .arg = "?",    .doc = "List valid algorithm kinds" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "kind", required_argument, .val = 'k' },
        .off = offsetof(jcmd_opt_t, kinds),
        .set = opt_set_kind,
        .doc = doc_kind
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    json_decref(opt->kinds);
}

static int
cmp(const void *a, const void *b)
{
    const char *const *aa = a;
    const char *const *bb = b;
    return strcasecmp(*aa, *bb);
}

static bool
filter(const jcmd_opt_t *opt, jose_hook_alg_kind_t kind)
{
    size_t size = 0;

    size = json_array_size(opt->kinds);
    if (size == 0)
        return true;

    for (size_t i = 0; i < size; i++) {
        if (kind == name2kind(json_string_value(json_array_get(opt->kinds, i))))
            return true;
    }

    return false;
}

static int
jcmd_alg(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    size_t len = 0;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (filter(&opt, a->kind))
            len++;
    }

    const char *names[len];

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (filter(&opt, a->kind))
            names[--len] = a->name;
    }

    qsort(names, sizeof(names) / sizeof(*names), sizeof(*names), cmp);

    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++)
        fprintf(stdout, "%s\n", names[i]);

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_alg, "alg")
