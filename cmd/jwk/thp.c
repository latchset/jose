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
#include "../../lib/hooks.h"
#include <string.h>
#include <unistd.h>

#define SUMMARY "Calculates the JWK thumbprint"

typedef struct {
    const char *hash;
    const char *find;
    json_t *keys;
    FILE *output;
} jcmd_opt_t;

static const char *prefix =
"jose jwk thp -i JWK [-a ALG] [-o THP]\n\n" SUMMARY;

static bool
opt_set_thp(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    const char **find = vopt;
    *find = arg;
    return true;
}

static bool
opt_set_hash(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    const char **hash = vopt;

    if (strcmp(arg, "?") == 0) {
        for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
            if (a->kind == JOSE_HOOK_ALG_KIND_HASH)
                fprintf(stdout, "%s\n", a->name);
        }

        exit(EXIT_SUCCESS);
    }

    if (!jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, arg))
        return false;

    *hash = arg;
    return true;
}

static const jcmd_doc_t doc_hash[] = {
    { .arg = "ALG", .doc = "Use the specified hash algorithm (case sensitive)" },
    { .arg = "?",   .doc = "List available hash algorithms" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc="Write thumbprint(s) to FILE" },
    { .arg = "-",    .doc="Write thumbprint(s) to standard input" },
    {}
};

static const jcmd_doc_t doc_find[] = {
    { .arg = "THP", .doc = "Search input keys for JWK with the given thumbprint" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = jcmd_jwk_doc_input,
    },
    {
        .opt = { "algorithm", required_argument, .val = 'a' },
        .off = offsetof(jcmd_opt_t, hash),
        .set = opt_set_hash,
        .doc = doc_hash,
        .def = "S1",
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, output),
        .doc = doc_output,
        .set = jcmd_opt_set_ofile,
        .def = "-",
    },
    {
        .opt = { "find", required_argument, .val = 'f' },
        .off = offsetof(jcmd_opt_t, find),
        .doc = doc_find,
        .set = opt_set_thp
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
jcmd_jwk_thp(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    size_t elen = 0;
    size_t dlen = 0;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (json_array_size(opt.keys) == 0) {
        fprintf(stderr, "Must specify JWK(Set)!\n");
        return EXIT_FAILURE;
    }

    dlen = jose_jwk_thp_buf(NULL, NULL, opt.hash, NULL, 0);
    if (dlen == SIZE_MAX) {
        fprintf(stderr, "Error determining hash size!\n");
        return EXIT_FAILURE;
    }

    elen = jose_b64_enc_buf(NULL, dlen, NULL, 0);
    if (elen == SIZE_MAX)
        return EXIT_FAILURE;

    for (size_t i = 0; i < json_array_size(opt.keys); i++) {
        const json_t *jwk = json_array_get(opt.keys, i);

        for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
            uint8_t dec[dlen];
            char enc[elen];

            if (a->kind != JOSE_HOOK_ALG_KIND_HASH)
                continue;

            if (!opt.find && strcmp(opt.hash, a->name) != 0)
                continue;

            if (!jose_jwk_thp_buf(NULL, jwk, opt.hash, dec, sizeof(dec))) {
                fprintf(stderr, "Error making thumbprint!\n");
                return EXIT_FAILURE;
            }

            if (jose_b64_enc_buf(dec, dlen, enc, sizeof(enc)) != elen)
                return EXIT_FAILURE;

            if (!opt.find) {
                if (fwrite(enc, 1, elen, opt.output) != elen)
                    return EXIT_FAILURE;

                if (json_array_size(opt.keys) > 1 ||
                    isatty(fileno(opt.output))) {
                    if (fprintf(opt.output, "\n") != 1)
                        return EXIT_FAILURE;
                }
            } else if (strlen(opt.find) == elen &&
                       strncmp(opt.find, enc, elen) == 0) {
                static const int flags = JSON_COMPACT | JSON_SORT_KEYS;

                if (json_dumpf(jwk, opt.output, flags) < 0)
                    return EXIT_FAILURE;

                return EXIT_SUCCESS;
           }
        }
    }

    return opt.find ? EXIT_FAILURE : EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_thp, "jwk", "thp")
