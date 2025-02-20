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
#include <unistd.h>
#include <string.h>

#define SUMMARY "Creates a random JWK for each input JWK template"

typedef struct {
    FILE *output;
    json_t *keys;
    bool set;
} jcmd_opt_t;

static const char *prefix =
"jose jwk gen -i JWK [-s] [-o JWK]\n\n" SUMMARY;

static const jcmd_doc_t doc_input[] = {
    { .arg = "JSON", .doc="Parse JWK(Set) template from JSON" },
    { .arg = "FILE", .doc="Read JWK(Set) template from FILE" },
    { .arg = "-",    .doc="Read JWK(Set) template from standard input" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument,  .val = 'i' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwkt,
        .doc = doc_input,
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

static int jcmd_jwk_invalid_key(const char* key, const char* msg) {
    int invalid_key = strcmp(key, "kty") && strcmp(key, "alg");
    if (invalid_key)
        fprintf(stderr, "%s, unknown json key:%s\n", msg, key);
    return invalid_key;
}

static int jcmd_jwk_invalid_algo(const json_t* value, const char* msg) {
    if (json_is_string(value)) {
        const char* algo = json_string_value(value);
        if (!jose_hook_alg_find_any(algo)) {
            fprintf(stderr, "%s, unknown algorithm:%s\n", msg, algo);
            return 1;
        }
    }
    return 0;
}

static int
jcmd_jwk_dump_error(json_t* elem)
{
    if (!json_is_object(elem))
        return -1;

    for (void* iter = json_object_iter(elem); iter;
         iter = json_object_iter_next(elem, iter)) {
        const char* msg = "JWK generation failed";
        const char* key = json_object_iter_key(iter);
        if (jcmd_jwk_invalid_key(key, msg) ||
            jcmd_jwk_invalid_algo(json_object_iter_value(iter), msg)) {
            break;
        }
    }
    return 0;
}

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_file_cleanup(&opt->output);
    json_decrefp(&opt->keys);
}

static int
jcmd_jwk_gen(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (json_array_size(opt.keys) == 0) {
        fprintf(stderr, "At least one JWK template is required!\n");
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < json_array_size(opt.keys); i++) {
        if (!jose_jwk_gen(NULL, json_array_get(opt.keys, i))) {
            if (jcmd_jwk_dump_error(json_array_get(opt.keys, i)) < 0)
                fprintf(stderr, "JWK generation failed! (unknown issue)\n");
            return EXIT_FAILURE;
        }
    }

    if (json_array_size(opt.keys) == 1 && !opt.set) {
        if (json_dumpf(json_array_get(opt.keys, 0), opt.output,
                       JSON_COMPACT | JSON_SORT_KEYS) < 0) {
            fprintf(stderr, "Error dumping JWK!\n");
            return EXIT_FAILURE;
        }
    } else {
        json_auto_t *jwks = NULL;

        jwks = json_pack("{s:O}", "keys", opt.keys);
        if (!jwks)
            return EXIT_FAILURE;

        if (json_dumpf(jwks, opt.output, JSON_COMPACT | JSON_SORT_KEYS) < 0) {
            fprintf(stderr, "Error dumping JWKSet!\n");
            return EXIT_FAILURE;
        }
    }

    if (isatty(fileno(opt.output)))
        fprintf(opt.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_gen, "jwk", "gen")
