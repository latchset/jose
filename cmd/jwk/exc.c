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
#include <string.h>
#include <unistd.h>

#define SUMMARY "Performs a key exchange using the two input keys"

typedef struct {
    FILE *output;
    json_t *keys;
    json_t *lcl;
    json_t *rem;
} jcmd_opt_t;

static const char *prefix =
"jose jwk exc [-i JWK] -l JWK -r JWK [-o JWK]\n\n" SUMMARY;

static const jcmd_doc_t doc_input[] = {
    { .arg = "JSON", .doc="Parse JWK template from JSON" },
    { .arg = "FILE", .doc="Read JWK template from FILE" },
    { .arg = "-",    .doc="Read JWK template from standard input" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc="Write JWK to FILE" },
    { .arg = "-",    .doc="Write JWK to standard input" },
    {}
};

static const jcmd_doc_t doc_local[] = {
    { .arg = "FILE", .doc="Read local JWK from FILE" },
    { .arg = "-",    .doc="Read local JWK from standard input" },
    {}
};

static const jcmd_doc_t doc_remote[] = {
    { .arg = "FILE", .doc="Read remote JWK from FILE" },
    { .arg = "-",    .doc="Read remote JWK from standard input" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwkt,
        .doc = doc_input,
        .def = "{}",
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, output),
        .set = jcmd_opt_set_ofile,
        .doc = doc_output,
        .def = "-",
    },
    {
        .opt = { "local", required_argument, .val = 'l' },
        .off = offsetof(jcmd_opt_t, lcl),
        .set = jcmd_opt_set_jwks,
        .doc = doc_local,
    },
    {
        .opt = { "remote", required_argument, .val = 'r' },
        .off = offsetof(jcmd_opt_t, rem),
        .set = jcmd_opt_set_jwks,
        .doc = doc_remote,
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_file_cleanup(&opt->output);
    json_decrefp(&opt->keys);
    json_decrefp(&opt->lcl);
    json_decrefp(&opt->rem);
}

static int
jcmd_jwk_exc(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    json_auto_t *key = NULL;
    json_t *tmpl = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (json_array_size(opt.keys) > 1 && json_array_remove(opt.keys, 0) < 0)
        return EXIT_FAILURE;

    if (json_array_size(opt.lcl) != 1) {
        fprintf(stderr, "Local JWK must be specified exactly once!\n");
        return EXIT_FAILURE;
    }

    if (json_array_size(opt.rem) != 1) {
        fprintf(stderr, "Remote JWK must be specified exactly once!\n");
        return EXIT_FAILURE;
    }

    key = jose_jwk_exc(NULL, json_array_get(opt.lcl, 0),
                       json_array_get(opt.rem, 0));
    if (!key) {
        fprintf(stderr, "Error performing exchange!\n");
        return EXIT_FAILURE;
    }

    tmpl = json_array_get(opt.keys, json_array_size(opt.keys) - 1);

    if (json_object_update(tmpl, key) < 0)
        return EXIT_FAILURE;

    if (json_dumpf(tmpl, opt.output, JSON_COMPACT | JSON_SORT_KEYS) < 0) {
        fprintf(stderr, "Error writing JWK!\n");
        return EXIT_FAILURE;
    }

    if (isatty(fileno(opt.output)))
        fprintf(opt.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_exc, "jwk", "exc")
