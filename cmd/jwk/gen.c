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

#define SUMMARY "Creates a random JWK for each input JWK template"
#define START "{ \"kty\": \"EC\", \"crv\": \"P-256\""
#define KEYS ", \"x\": \"...\", \"y\": \"...\", \"d\": \"...\""
#define END " }"

typedef struct {
    FILE *output;
    json_t *keys;
} jcmd_opt_t;

static const char *prefix =
"jose jwk gen -i JWK [-o JWK]\n\n" SUMMARY;

static const char *suffix =
"\nThe simplest way to create a new key is to specify the algorithm that "
"\nwill be used with the key. For example:"
"\n"
"\n    $ jose jwk gen -i '{\"alg\":\"A128GCM\"}'"
"\n    { \"kty\": \"oct\", \"k\": \"...\", \"alg\": \"A128GCM\","
"\n      \"use\": \"enc\", \"key_ops\": [\"encrypt\", \"decrypt\"] }"
"\n"
"\n    $ jose jwk gen -i '{\"alg\":\"RSA1_5\"}'"
"\n    { \"kty\": \"RSA\", \"alg\": \"RSA1_5\", \"use\": \"enc\","
"\n      \"key_ops\": [\"wrapKey\", \"unwrapKey\"], ... }"
"\n"
"\nNote that when specifying an algorithm, default parameters such as "
"\n\"use\" and \"key_ops\" will be created if not specified."
"\n"
"\nAlternatively, key parameters can be specified directly:"
"\n"
"\n    $ jose jwk gen -i '" START END "'"
"\n    " START KEYS END "\n"
"\n    $ jose jwk gen -i '{\"kty\": \"oct\", \"bytes\": 32}'"
"\n    { \"kty\": \"oct\", \"k\": \"...\" }\n"
"\n    $ jose jwk gen -i '{\"kty\": \"RSA\", \"bits\": 4096}'"
"\n    { \"kty\": \"RSA\", \"n\": \"...\", \"e\": \"...\", ... }"
"\n"
"\nIf there is more than one input JWK template, the output is a JWKSet:"
"\n"
"\n    $ jose jwk gen -i '{\"alg\":\"A128GCM\"}' -i '{\"alg\":\"RSA1_5\"}'"
"\n    { \"keys\": [...] }";

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
        .set = jcmd_opt_set_jwks,
        .doc = doc_input,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, output),
        .doc = jcmd_jwk_doc_output,
        .set = jcmd_opt_set_ofile,
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
jcmd_jwk_gen(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix, suffix))
        return EXIT_FAILURE;

    if (json_array_size(opt.keys) == 0) {
        fprintf(stderr, "At least one JWK template is required!\n");
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < json_array_size(opt.keys); i++) {
        if (!jose_jwk_gen(NULL, json_array_get(opt.keys, i))) {
            fprintf(stderr, "JWK generation failed!\n");
            return EXIT_FAILURE;
        }
    }

    if (json_array_size(opt.keys) == 1) {
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
