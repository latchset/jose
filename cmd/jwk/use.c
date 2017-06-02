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

#define SUMMARY "Validates the permissions of a key for the specified use(s)"

typedef struct {
    FILE *output;
    json_t *keys;
    json_t *uses;
    bool req;
    bool all;
} jcmd_opt_t;

static const char *prefix =
"jose jwk use -i JWK [-a] [-r] -u OP\n\n" SUMMARY;

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_file_cleanup(&opt->output);
    json_decrefp(&opt->keys);
    json_decrefp(&opt->uses);
}

static bool
opt_set_use(void *vopt, const char *arg)
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
    {}
};

static int
jcmd_jwk_use(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = {};
    const json_t *jwk = NULL;

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

    if (json_array_size(opt.keys) > 1) {
        fprintf(stderr, "Too many JWKs specified!\n");
        return EXIT_FAILURE;
    }

    jwk = json_array_get(opt.keys, 0);

    for (size_t i = 0; i < json_array_size(opt.uses); i++) {
        const char *use = json_string_value(json_array_get(opt.uses, i));
        bool allowed = jose_jwk_prm(NULL, jwk, opt.req, use);
        if (opt.all && !allowed)
            return EXIT_FAILURE;
        if (!opt.all && allowed)
            return EXIT_SUCCESS;
    }

    return opt.all ? EXIT_SUCCESS : EXIT_FAILURE;
}

JCMD_REGISTER(SUMMARY, jcmd_jwk_use, "jwk", "use")
