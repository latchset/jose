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

#include "b64.h"
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#define SUMMARY "Decodes URL-safe Base64 data to binary"

static const char *prefix = "jose b64 dec -i B64 [-O BIN]\n\n" SUMMARY;

static const jcmd_doc_t doc_input[] = {
    { .arg = "FILE", .doc="Read Base64 (URL-safe) data from FILE" },
    { .arg = "-",    .doc="Read Base64 (URL-safe) data from standard input" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc="Write binary data to FILE" },
    { .arg = "-",    .doc="Write binary data to standard output" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "base64", required_argument, .val = 'i' },
        .off = offsetof(jcmd_b64_opt_t, input),
        .set = jcmd_opt_set_ifile,
        .doc = doc_input,
    },
    {
        .opt = { "binary", required_argument, .val = 'O' },
        .off = offsetof(jcmd_b64_opt_t, output),
        .set = jcmd_opt_set_ofile,
        .doc = doc_output,
        .def = "-",
    },
    {}
};

static int
jcmd_b64_dec(int argc, char *argv[])
{
    jcmd_b64_opt_auto_t opt = {};
    jose_io_auto_t *b64 = NULL;
    jose_io_auto_t *out = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (!opt.input) {
        fprintf(stderr, "Input not specified!\n");
        return EXIT_FAILURE;
    }

    out = jose_io_file(NULL, opt.output);
    if (!out)
        return EXIT_FAILURE;

    b64 = jose_b64_dec_io(out);
    if (!b64)
        return EXIT_FAILURE;

    for (int c = fgetc(opt.input); c != EOF; c = fgetc(opt.input)) {
        uint8_t b = c;

        if (isspace(c))
            continue;

        if (!b64->feed(b64, &b, sizeof(b)))
            return EXIT_FAILURE;
    }

    if (!b64->done(b64))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_b64_dec, "b64", "dec")
