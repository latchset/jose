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

#define SUMMARY "Validates the permissions of a key for the specified use(s)"

typedef struct {
    FILE *output;
    json_t *keys;
    json_t *uses;
    bool req;
    bool all;
    bool set;
} jcmd_opt_t;

static const char *prefix =
"jose jwk use -i JWK [-a] [-r] -u OP [-o JWK [-s]]\n\n" SUMMARY;

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_file_cleanup(&opt->output);
    json_decrefp(&opt->keys);
    json_decrefp(&opt->uses);
}

static bool
opt_set_use(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_t **uses = vopt;

    if (!*uses)
        *uses = json_array();

    return json_array_append_new(*uses, json_string(arg)) == 0;
}

static const jcmd_doc_t doc_use[] = {
    { .arg = "sign",       .doc = "Validate the key for signing" },
    { .arg = "verify",     .doc = "Validate the key for verifying" },
    { .arg = "encrypt",    .doc = "Validate the key for encrypting" },
    { .arg = "decrypt",    .doc = "Validate the key for decrypting" },
    { .arg = "wrapKey",    .doc = "Validate the key for wrapping" },
    { .arg = "unwrapKey",  .doc = "Validate the key for unwrapping" },
    { .arg = "deriveKey",  .doc = "Validate the key for deriving keys" },
    { .arg = "deriveBits", .doc = "Validate the key for deriving bits" },
    {}
};

static const jcmd_doc_t doc_all[] = {
    { .doc = "Succeeds only if all operations are allowed" },
    {}
};

static const jcmd_doc_t doc_req[] = {
    { .doc = "Operations must be explicitly allowed" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc = "Filter keys to FILE as JWK(Set)" },
    { .arg = "-",    .doc = "Filter keys to standard output as JWK(Set)" },
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
        .opt = { "use", required_argument, .val = 'u' },
        .off = offsetof(jcmd_opt_t, uses),
        .set = opt_set_use,
        .doc = doc_use,
    },
    {
        .opt = { "all", no_argument, .val = 'a' },
        .off = offsetof(jcmd_opt_t, all),
        .set = jcmd_opt_set_flag,
        .doc = doc_all,
    },
    {
        .opt = { "required", no_argument, .val = 'r' },
        .off = offsetof(jcmd_opt_t, req),
        .set = jcmd_opt_set_flag,
        .doc = doc_req,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, output),
        .set = jcmd_opt_set_ofile,
        .doc = doc_output,
    },
    {
        .opt = { "set", no_argument, .val = 's' },
        .off = offsetof(jcmd_opt_t, set),
        .doc = jcmd_jwk_doc_set,
        .set = jcmd_opt_set_flag,
    },
    {}
};

static int
jcmd_jwk_use(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    json_auto_t *arr = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (json_array_size(opt.uses) == 0) {
        fprintf(stderr, "No uses specified!\n");
        return EXIT_FAILURE;
    }

    if (json_array_size(opt.keys) == 0) {
        fprintf(stderr, "No JWK specified!\n");
        return EXIT_FAILURE;
    }

    arr = json_array();
    if (!arr)
        return EXIT_FAILURE;

    for (size_t i = 0; i < json_array_size(opt.keys); i++) {
        json_t *jwk = json_array_get(opt.keys, i);
        bool status = false;

        for (size_t j = 0; j < json_array_size(opt.uses); j++) {
            const char *use = json_string_value(json_array_get(opt.uses, j));

            if (opt.all)
                status |= !jose_jwk_prm(NULL, jwk, opt.req, use);
            else
                status |= jose_jwk_prm(NULL, jwk, opt.req, use);
        }

        status = opt.all ? !status : status;

        if (opt.output) {
            if (status && json_array_append(arr, jwk) < 0)
                return EXIT_FAILURE;
        } else if (!status) {
            return EXIT_FAILURE;
        }
    }

    if (opt.output) {
        json_auto_t *jwkset = NULL;

        switch (json_array_size(arr)) {
        case 0: return EXIT_FAILURE;
        case 1:
            if (!opt.set) {
                jwkset = json_incref(json_array_get(arr, 0));
                break;
            }
            /* fallthrough */
        default:
            jwkset = json_pack("{s:O}", "keys", arr);
            break;
        }

        if (!jwkset)
            return EXIT_FAILURE;

        if (json_dumpf(jwkset, opt.output, JSON_COMPACT | JSON_SORT_KEYS) < 0)
            return EXIT_FAILURE;

        if (isatty(fileno(opt.output)))
            fprintf(opt.output, "\n");
    }

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_use, "jwk", "use")
