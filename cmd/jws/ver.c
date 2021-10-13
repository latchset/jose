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

#include "jws.h"
#include <string.h>
#include <unistd.h>

#define BLOCKS 1024
#define SUMMARY "Verifies a JWS using the supplied JWKs and outputs payload"

typedef struct {
    jcmd_opt_io_t io;
    json_t *keys;
    bool all;
} jcmd_opt_t;

static const char *prefix =
"jose jws ver -i JWS [-I PAY] -k JWK [-a] [-O PAY]\n\n" SUMMARY;

static const jcmd_doc_t doc_all[] = {
    { .doc="Ensure the JWS validates with all keys" },
    {}
};

static const jcmd_doc_t doc_detach[] = {
    { .arg = "FILE", .doc="Decode payload to FILE" },
    { .arg = "-",    .doc="Decode payload to standard output" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, io),
        .set = jcmd_opt_io_set_input,
        .doc = jcmd_jws_doc_input,
    },
    {
        .opt = { "detached", required_argument, .val = 'I' },
        .off = offsetof(jcmd_opt_t, io.detached),
        .set = jcmd_opt_set_ifile,
        .doc = jcmd_jws_doc_detached,
    },
    {
        .opt = { "key", required_argument, .val = 'k' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = jcmd_doc_key,
    },
    {
        .opt = { "detach", required_argument, .val = 'O' },
        .off = offsetof(jcmd_opt_t, io.detach),
        .set = jcmd_opt_set_ofile,
        .doc = doc_detach,
    },
    {
        .opt = { "all", no_argument, .val = 'a' },
        .off = offsetof(jcmd_opt_t, all),
        .set = jcmd_opt_set_flag,
        .doc = doc_all,
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *sig)
{
    jcmd_opt_io_cleanup(&sig->io);
    json_decref(sig->keys);
}

static bool
validate_input(const jcmd_opt_t *opt, json_t **sigs)
{
    if (json_array_size(opt->keys) == 0) {
        fprintf(stderr, "MUST specify a JWK(Set)!\n");
        return false;
    }

    if (!opt->io.obj) {
        fprintf(stderr, "Invalid JWS!\n");
        return false;
    }

    *sigs = json_incref(json_object_get(opt->io.obj, "signatures"));
    if (!*sigs)
        *sigs = json_pack("[O]", opt->io.obj);
    if (!json_is_array(*sigs)) {
        fprintf(stderr, "Signatures value must be an array!\n");
        return false;
    }

    return true;
}

static int
jcmd_jws_ver(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = { .io.fields = jcmd_jws_fields };
    jose_io_auto_t *io = NULL;
    json_auto_t *sigs = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (!validate_input(&opt, &sigs))
        return EXIT_FAILURE;

    io = jose_jws_ver_io(NULL, opt.io.obj, NULL, opt.keys, opt.all);
    io = jcmd_jws_prep_io(&opt.io, io);
    if (!io) {
        fprintf(stderr, "Error initializing signature context!\n");
        return EXIT_FAILURE;
    }

    if (opt.io.detached || opt.io.input) {
        FILE *f = opt.io.detached ? opt.io.detached : opt.io.input;

        for (int c = fgetc(f); c != EOF; c = fgetc(f)) {
            uint8_t b = c;

            if (!opt.io.detached && b == '.')
                break;

            if (!io->feed(io, &b, sizeof(b)))
                return EXIT_FAILURE;
        }

        for (int c = 0; opt.io.detached && opt.io.input && c != EOF && c != '.'; )
            c = fgetc(opt.io.input);
    } else {
        const char *pay = NULL;
        size_t payl = 0;

        if (json_unpack(opt.io.obj, "{s?s%}", "payload", &pay, &payl) < 0)
            return EXIT_FAILURE;

        if (!io->feed(io, pay ? pay : "", payl))
            return EXIT_FAILURE;
    }

    if (opt.io.input) {
        if (json_object_set_new(opt.io.obj, "signature",
                                jcmd_compact_field(opt.io.input)) < 0) {
            fprintf(stderr, "Error reading last compact field!\n");
            return EXIT_FAILURE;
        }
    }

    if (!io->done(io)) {
        fprintf(stderr, "Signature validation failed!\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jws_ver, "jws", "ver")
