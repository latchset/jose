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

#define SUMMARY "Signs a payload using one or more JWKs and outputs a JWS"

typedef struct {
    jcmd_opt_io_t io;
    json_t *keys;
    json_t *sigs;
} jcmd_opt_t;

static const char *prefix =
"jose jws sig [-i JWS] [-I PAY] [-s SIG] -k JWK [-o JWS] [-O PAY] [-c]"
"\n\n" SUMMARY;

static const jcmd_doc_t doc_input[] = {
    { .arg = "JSON", .doc="Parse JWS template from JSON" },
    { .arg = "FILE", .doc="Read JWS template from FILE" },
    { .arg = "-",    .doc="Read JWS template from standard input" },
    {}
};

static const jcmd_doc_t doc_signature[] = {
    { .arg = "JSON", .doc="Parse JWS signature template from JSON" },
    { .arg = "FILE", .doc="Read JWS signature template from FILE" },
    { .arg = "-",    .doc="Read JWS signature template standard input" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, io),
        .set = jcmd_opt_io_set_input,
        .doc = doc_input,
        .def = "{}",
    },
    {
        .opt = { "detached", required_argument, .val = 'I' },
        .off = offsetof(jcmd_opt_t, io.detached),
        .set = jcmd_opt_set_ifile,
        .doc = jcmd_jws_doc_detached,
    },
    {
        .opt = { "signature", required_argument, .val = 's' },
        .off = offsetof(jcmd_opt_t, sigs),
        .set = jcmd_opt_set_jsons,
        .doc = doc_signature,
        .def = "{}",
    },
    {
        .opt = { "key", required_argument, .val = 'k' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = jcmd_doc_key,
    },
    {
        .opt = { "pem", required_argument, .val = 'p' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_pem,
        .doc = jcmd_doc_pem,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, io.output),
        .set = jcmd_opt_set_ofile,
        .doc = jcmd_jws_doc_output,
        .def = "-",
    },
    {
        .opt = { "detach", required_argument, .val = 'O' },
        .off = offsetof(jcmd_opt_t, io.detach),
        .set = jcmd_opt_set_ofile,
        .doc = jcmd_jws_doc_detach,
    },
    {
        .opt = { "compact", no_argument, .val = 'c' },
        .off = offsetof(jcmd_opt_t, io.compact),
        .set = jcmd_opt_set_flag,
        .doc = jcmd_jws_doc_compact,
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_opt_io_cleanup(&opt->io);
    json_decref(opt->keys);
    json_decref(opt->sigs);
}

static bool
validate_input(jcmd_opt_t *opt)
{
    size_t nsigs = 0;

    if (json_array_remove(opt->sigs, 0) < 0)
        return false;

    if (json_array_size(opt->keys) == 0) {
        fprintf(stderr, "At least one JWK is required to sign!\n");
        return false;
    }

    if (json_array_size(opt->keys) < json_array_size(opt->sigs)) {
        fprintf(stderr, "Specified more signature templates than JWKs!\n");
        return false;
    }

    nsigs += json_array_size(opt->keys);

    if (json_is_array(json_object_get(opt->io.obj, "signatures")))
        nsigs += json_array_size(json_object_get(opt->io.obj, "signatures"));

    if (json_object_get(opt->io.obj, "protected") ||
        json_object_get(opt->io.obj, "signature"))
        nsigs += 1;

    if (opt->io.compact && nsigs > 1) {
        fprintf(stderr, "Too many signatures for compact serialization!\n");
        return false;
    }

    if (json_array_size(opt->keys) < json_array_size(opt->sigs)) {
        fprintf(stderr, "Specified more signatures than keys!\n");
        return false;
    }

    while (json_array_size(opt->sigs) < json_array_size(opt->keys)) {
        if (json_array_append_new(opt->sigs, json_object()) < 0)
            return false;
    }

    return true;
}

static int
jcmd_jws_sig(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = { .io.fields = jcmd_jws_fields };
    jose_io_auto_t *io = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (!validate_input(&opt))
        return EXIT_FAILURE;

    io = jose_jws_sig_io(NULL, opt.io.obj, opt.sigs, opt.keys);
    if (!io)
        return EXIT_FAILURE;

    io = jcmd_jws_prep_io(&opt.io, io);
    if (!io)
        return EXIT_FAILURE;

    if (opt.io.compact) {
        const char *v = NULL;
        json_t *o = json_array_get(opt.sigs, 0);

        if (json_unpack(o, "{s?s}", "protected", &v) < 0)
            return EXIT_FAILURE;

        fprintf(opt.io.output, "%s.", v ? v : "");
    } else {
        fprintf(opt.io.output, "{");
        if (!opt.io.detach)
            fprintf(opt.io.output, "\"payload\":\"");
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

    if (!io->done(io))
        return EXIT_FAILURE;

    if (opt.io.compact) {
        const char *v = NULL;

        if (json_unpack(opt.io.obj, "{s:s}", "signature", &v) < 0) {
            fprintf(stderr, "Missing signature parameter!\n");
            return EXIT_FAILURE;
        }

        fprintf(opt.io.output, ".%s", v);
    } else {
        if (!opt.io.detach)
            fprintf(opt.io.output, "\",");
        json_dumpf(opt.io.obj, opt.io.output,
                   JSON_EMBED | JSON_COMPACT | JSON_SORT_KEYS);
        fprintf(opt.io.output, "}");
    }

    if (isatty(fileno(opt.io.output)))
        fprintf(opt.io.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jws_sig, "jws", "sig")
