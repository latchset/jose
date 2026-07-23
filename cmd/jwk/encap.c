/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2026 Red Hat, Inc.
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
#include <unistd.h>

#define SUMMARY "Performs KEM encapsulation using a public key"

typedef struct {
    FILE *output;
    json_t *keys;
} jcmd_opt_t;

static const char *prefix =
"jose jwk encap -i JWK [-o JSON]\n\n" SUMMARY;

static const jcmd_doc_t doc_input[] = {
    { .arg = "JSON", .doc="Parse public JWK from JSON" },
    { .arg = "FILE", .doc="Read public JWK from FILE" },
    { .arg = "-",    .doc="Read public JWK from standard input" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc="Write result to FILE" },
    { .arg = "-",    .doc="Write result to standard output" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = doc_input,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, output),
        .set = jcmd_opt_set_ofile,
        .doc = doc_output,
        .def = "-",
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
jcmd_jwk_encap(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    json_auto_t *result = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (json_array_size(opt.keys) != 1) {
        fprintf(stderr, "Public JWK must be specified exactly once!\n");
        return EXIT_FAILURE;
    }

    result = jose_jwk_kem_enc(NULL, json_array_get(opt.keys, 0));
    if (!result) {
        fprintf(stderr, "Error performing encapsulation!\n");
        return EXIT_FAILURE;
    }

    if (json_dumpf(result, opt.output, JSON_COMPACT | JSON_SORT_KEYS) < 0) {
        fprintf(stderr, "Error writing result!\n");
        return EXIT_FAILURE;
    }

    if (isatty(fileno(opt.output)))
        fprintf(opt.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_encap, "jwk", "encap")
