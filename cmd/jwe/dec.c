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

#include "jwe.h"
#include <unistd.h>
#include <string.h>

#define SUMMARY "Decrypts a JWE using the supplied JWKs and outputs plaintext"

typedef struct {
    jcmd_opt_io_t io;
    json_t *keys;
    bool pwd;
} jcmd_opt_t;

static const char *prefix =
"jose jwe dec -i JWE [-I CT] -k JWK [-p] [-O PT]\n\n" SUMMARY;

static const jcmd_doc_t doc_password[] = {
    { .doc="Prompt for a decryption password, if necessary" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, io),
        .set = jcmd_opt_io_set_input,
        .doc = jcmd_jwe_doc_input,
    },
    {
        .opt = { "detached", required_argument, .val = 'I' },
        .off = offsetof(jcmd_opt_t, io.detached),
        .set = jcmd_opt_set_ifile,
        .doc = jcmd_jwe_doc_detached,
    },
    {
        .opt = { "password", no_argument, .val = 'p' },
        .off = offsetof(jcmd_opt_t, pwd),
        .set = jcmd_opt_set_flag,
        .doc = doc_password,
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
        .doc = jcmd_jwe_doc_input,
        .def = "-",
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_opt_io_cleanup(&opt->io);
    json_decref(opt->keys);
}

static bool
header_has_pbes2(const json_t *jwe, const json_t *rcp)
{
    json_auto_t *hdr = NULL;
    const char *alg = NULL;

    hdr = jose_jwe_hdr(jwe, rcp);
    if (!hdr)
        return false;

    if (json_unpack(hdr, "{s:s}", "alg", &alg) < 0)
        return false;

    return strncmp(alg, "PBES2", strlen("PBES2")) == 0;
}

static bool
jwe_has_pbes2(const json_t *jwe)
{
    json_t *rcps = NULL;

    rcps = json_object_get(jwe, "recipients");
    if (!json_is_array(rcps))
        return header_has_pbes2(jwe, jwe);

    for (size_t i = 0; i < json_array_size(rcps); i++) {
        if (header_has_pbes2(jwe, json_array_get(rcps, i)))
            return true;
    }

    return false;
}

static json_t *
unwrap(const json_t *jwe, const json_t *jwks, bool prompt)
{
    json_auto_t *cek = NULL;

    cek = jose_jwe_dec_jwk(NULL, jwe, NULL, jwks);
    if (!cek && jwe_has_pbes2(jwe) && prompt) {
        const char *pwd = NULL;

        pwd = getpass("Please enter decryption password: ");
        if (pwd) {
            json_auto_t *jwk = json_string(pwd);
            cek = jose_jwe_dec_jwk(NULL, jwe, NULL, jwk);
        }
    }

    return json_incref(cek);
}

static int
jcmd_jwe_dec(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = { .io.fields = jcmd_jwe_fields };
    jose_io_auto_t *dec = NULL;
    jose_io_auto_t *out = NULL;
    json_auto_t *cek = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (!opt.io.obj) {
        fprintf(stderr, "Invalid JWE!\n");
        return EXIT_FAILURE;
    }

    if (json_array_size(opt.keys) == 0 && !opt.pwd) {
        fprintf(stderr, "MUST specify a JWK in non-interactive mode!\n\n");
        return EXIT_FAILURE;
    }

    cek = unwrap(opt.io.obj, opt.keys, opt.pwd);
    if (!cek) {
        fprintf(stderr, "Unwrapping failed!\n");
        return EXIT_FAILURE;
    }

    out = jose_io_file(NULL, opt.io.detach);
    if (!out)
        return EXIT_FAILURE;

    dec = jose_jwe_dec_cek_io(NULL, opt.io.obj, cek, out);
    if (!dec)
        return EXIT_FAILURE;

    if (!opt.io.detached) {
        jose_io_auto_t *b64 = NULL;

        b64 = jose_b64_dec_io(dec);
        if (!b64)
            return EXIT_FAILURE;

        jose_io_auto(&dec);
        dec = jose_io_incref(b64);
    }

    if (opt.io.detached || opt.io.input) {
        FILE *f = opt.io.detached ? opt.io.detached : opt.io.input;

        for (int c = fgetc(f); c != EOF; c = fgetc(f)) {
            uint8_t b = c;

            if (!opt.io.detached && b == '.')
                break;

            if (!dec->feed(dec, &b, sizeof(b)))
                return EXIT_FAILURE;
        }

        for (int c = 0; opt.io.detached && opt.io.input && c != EOF && c != '.'; )
            c = fgetc(opt.io.input);
    } else {
        const char *ct = NULL;
        size_t ctl = 0;

        if (json_unpack(opt.io.obj, "{s:s%}", "ciphertext", &ct, &ctl) < 0)
            return EXIT_FAILURE;

        if (!dec->feed(dec, ct, ctl))
            return EXIT_FAILURE;
    }

    if (opt.io.input) {
        if (json_object_set_new(opt.io.obj, "tag",
                                jcmd_compact_field(opt.io.input)) < 0) {
            fprintf(stderr, "Error reading last compact field!\n");
            return EXIT_FAILURE;
        }
    }

    if (!dec->done(dec))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

JCMD_REGISTER(SUMMARY, jcmd_jwe_dec, "jwe", "dec")
