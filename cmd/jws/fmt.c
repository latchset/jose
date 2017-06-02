/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
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

#define SUMMARY "Converts a JWS between serialization formats"

static const char *prefix =
"jose jws fmt -i JWS [-I PAY] [-o JWS] [-O PAY] [-c]\n\n" SUMMARY;

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .set = jcmd_opt_io_set_input,
        .doc = jcmd_jws_doc_input,
    },
    {
        .opt = { "detached", required_argument, .val = 'I' },
        .off = offsetof(jcmd_opt_io_t, detached),
        .set = jcmd_opt_set_ifile,
        .doc = jcmd_jws_doc_detached,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_io_t, output),
        .set = jcmd_opt_set_ofile,
        .doc = jcmd_jws_doc_output,
        .def = "-",
    },
    {
        .opt = { "detach", required_argument, .val = 'O' },
        .off = offsetof(jcmd_opt_io_t, detach),
        .set = jcmd_opt_set_ofile,
        .doc = jcmd_jws_doc_detach,
    },
    {
        .opt = { "compact", no_argument, .val = 'c' },
        .off = offsetof(jcmd_opt_io_t, compact),
        .set = jcmd_opt_set_flag,
        .doc = jcmd_jws_doc_compact,
    },
    {}
};

static int
jcmd_jws_fmt(int argc, char *argv[])
{
    jcmd_opt_io_auto_t opt = { .fields = jcmd_jws_fields };
    jose_io_auto_t *io = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    io = jcmd_jws_prep_io(&opt, NULL);
    if (!io)
        return EXIT_FAILURE;

    if (opt.compact) {
        const jcmd_field_t *f = &jcmd_jws_fields[0];
        const char *k = f->name;
        const char *v = NULL;

        if (json_unpack(opt.obj, "{s:[{s?s}!]}", f->mult, k, &v) < 0 &&
            json_unpack(opt.obj, "{s?s}", k, &v) < 0) {
            fprintf(stderr, "Input JWS cannot be converted to compact.\n");
            return EXIT_FAILURE;
        }

        fprintf(opt.output, "%s.", v ? v : "");
    } else {
        fprintf(opt.output, "{");
        if (!opt.detach)
            fprintf(opt.output, "\"payload\":\"");
    }

    if (opt.detached || opt.input) {
        FILE *f = opt.detached ? opt.detached : opt.input;

        for (int c = fgetc(f); c != EOF; c = fgetc(f)) {
            uint8_t b = c;

            if (!opt.detached && b == '.')
                break;

            if (!io->feed(io, &b, sizeof(b)))
                return EXIT_FAILURE;
        }

        for (int c = 0; opt.detached && opt.input && c != EOF && c != '.'; )
            c = fgetc(opt.input);
    } else {
        const char *pay = NULL;
        size_t payl = 0;

        if (json_unpack(opt.obj, "{s?s%}", "payload", &pay, &payl) < 0)
            return EXIT_FAILURE;

        if (!io->feed(io, pay ? pay : "", payl))
            return EXIT_FAILURE;
    }

    if (!io->done(io))
        return EXIT_FAILURE;

    if (opt.input) {
        if (json_object_set_new(opt.obj, "signature",
                                jcmd_compact_field(opt.input)) < 0) {
            fprintf(stderr, "Error reading last compact field!\n");
            return EXIT_FAILURE;
        }
    }

    if (opt.compact) {
        const char *v = NULL;

        if (json_unpack(opt.obj, "{s:s}", "signature", &v) < 0 &&
            json_unpack(opt.obj, "{s:[{s:s}!]}",
                        "signatures", "signature", &v) < 0) {
            fprintf(stderr, "Missing signature parameter!\n");
            return EXIT_FAILURE;
        }

        fprintf(opt.output, ".%s", v);
    } else {
        if (!opt.detach)
            fprintf(opt.output, "\",");
        json_dumpf(opt.obj, opt.output,
                   JSON_EMBED | JSON_COMPACT | JSON_SORT_KEYS);
        fprintf(opt.output, "}");
    }

    if (isatty(fileno(opt.output)))
        fprintf(opt.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jws_fmt, "jws", "fmt")
