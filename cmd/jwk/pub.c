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

#include "jwk.h"
#include <unistd.h>

#define SUMMARY "Cleans private keys from a JWK"

typedef struct {
    FILE *output;
    json_t *keys;
    bool set;
} jcmd_opt_t;

static const char *prefix =
"jose jwk pub -i JWK [-s] [-o JWK]\n\n" SUMMARY;

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument,  .val = 'i' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = jcmd_jwk_doc_input,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, output),
        .doc = jcmd_jwk_doc_output,
        .set = jcmd_opt_set_ofile,
        .def = "-",
    },
    {
        .opt = { "set", no_argument, .val = 's' },
        .off = offsetof(jcmd_opt_t, set),
        .doc = jcmd_jwk_doc_set,
        .set = jcmd_opt_set_flag,
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_file_cleanup(&opt->output);
    json_decrefp(&opt->keys);
}

static int
jcmd_jwk_pub(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    json_auto_t *out = NULL;
    bool fail = false;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    for (size_t i = 0; !fail && i < json_array_size(opt.keys); i++)
        fail |= !jose_jwk_pub(NULL, json_array_get(opt.keys, i));
    if (fail) {
        fprintf(stderr, "Error removing private keys!\n");
        return EXIT_FAILURE;
    }

    switch (json_array_size(opt.keys)) {
    case 0:
        fprintf(stderr, "MUST specify at least one JWK(Set)!\n");
        return EXIT_FAILURE;

    case 1:
        if (!opt.set) {
            out = json_incref(json_array_get(opt.keys, 0));
            break;
        }
        /* fallthrough */

    default:
        out = json_pack("{s:O}", "keys", opt.keys);
        break;
    }

    if (json_dumpf(out, opt.output, JSON_SORT_KEYS | JSON_COMPACT) < 0) {
        fprintf(stderr, "Error dumping JWK(Set)!\n");
        return EXIT_FAILURE;
    }

    if (isatty(fileno(opt.output)))
        fprintf(opt.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_pub, "jwk", "pub")
