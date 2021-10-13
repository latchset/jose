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
#include <string.h>
#include <unistd.h>

#define SUMMARY "Encodes binary data to URL-safe Base64"

static const char *prefix = "jose b64 enc -I BIN [-o B64]\n\n" SUMMARY;

static const jcmd_doc_t doc_input[] = {
    { .arg = "FILE", .doc="Read binary data from FILE" },
    { .arg = "-",    .doc="Read binary data from standard input" },
    {}
};

static const jcmd_doc_t doc_output[] = {
    { .arg = "FILE", .doc="Write Base64 (URL-safe) to FILE" },
    { .arg = "-",    .doc="Write Base64 (URL-safe) to standard output" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "binary", required_argument, .val = 'I' },
        .off = offsetof(jcmd_b64_opt_t, input),
        .set = jcmd_opt_set_ifile,
        .doc = doc_input,
    },
    {
        .opt = { "base64", required_argument, .val = 'o' },
        .off = offsetof(jcmd_b64_opt_t, output),
        .set = jcmd_opt_set_ofile,
        .doc = doc_output,
        .def = "-",
    },
    {}
};

static int
jcmd_b64_enc(int argc, char *argv[])
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

    b64 = jose_b64_enc_io(out);
    if (!b64)
        return EXIT_FAILURE;

    for (int c = fgetc(opt.input); c != EOF; c = fgetc(opt.input)) {
        uint8_t b = c;

        if (!b64->feed(b64, &b, sizeof(b)))
            return EXIT_FAILURE;
    }

    if (!b64->done(b64))
        return EXIT_FAILURE;

    if (isatty(fileno(opt.output)))
        fprintf(opt.output, "\n");

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_b64_enc, "b64", "enc")
