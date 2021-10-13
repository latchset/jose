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

#include "jwk.h"
#include <string.h>

#define SUMMARY "Determines if two or more JWKs are equal"

typedef struct {
    json_t *keys;
} jcmd_opt_t;

static const char *prefix =
"jose jwk eql -i JWK -i JWK\n\n" SUMMARY;

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = jcmd_jwk_doc_input,
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    json_decrefp(&opt->keys);
}

static int
jcmd_jwk_eql(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (json_array_size(opt.keys) < 2) {
        fprintf(stderr, "Must specify at least two JWKs!\n");
        return EXIT_FAILURE;
    }

    for (size_t i = 1; i < json_array_size(opt.keys); i++) {
        const json_t *a = json_array_get(opt.keys, i - 1);
        const json_t *b = json_array_get(opt.keys, i);

        if (!jose_jwk_eql(NULL, a, b))
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_eql, "jwk", "eql")
