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
#include <string.h>
#include <unistd.h>

#define SUMMARY "Encrypts plaintext using one or more JWKs and outputs a JWE"

typedef struct {
    jcmd_opt_io_t io;
    json_t *keys;
    json_t *rcps;
} jcmd_opt_t;

static const char *prefix =
"jose jwe enc [-i JWE] -I PT [-r RCP] -k JWK [-p] [-o JWE] [-O CT] [-c]\n\n" SUMMARY;

static json_t *
prompt(void)
{
    const char *c = NULL;
    char *p = NULL;

    while (!p || !c || strcmp(p, c) != 0) {
        free(p);

        p = strdup(getpass("Please enter an encryption password: "));
        if (!p)
            continue;

        if (strlen(p) < 8) {
            fprintf(stderr, "Password too short!\n");
            continue;
        }

        c = getpass("Please re-enter the previous password: ");
    }

    free(p);
    return json_string(c);
}

static bool
opt_set_password(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_t **keys = vopt;

    if (!*keys)
        *keys = json_array();

    return json_array_append_new(*keys, json_null()) == 0;
}

static const jcmd_doc_t doc_recipient[] = {
    { .arg = "FILE", .doc="Read JWE recipient template from FILE" },
    { .arg = "-",    .doc="Read JWE recipient template from standard input" },
    {}
};

static const jcmd_doc_t doc_password[] = {
    { .doc="Prompt for an encryption password" },
    {}
};

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, io),
        .set = jcmd_opt_io_set_input,
        .doc = jcmd_jwe_doc_input,
        .def = "{}",
    },
    {
        .opt = { "detached", required_argument, .val = 'I' },
        .off = offsetof(jcmd_opt_t, io.detached),
        .set = jcmd_opt_set_ifile,
        .doc = jcmd_jwe_doc_detached,
    },
    {
        .opt = { "recipient", required_argument, .val = 'r' },
        .off = offsetof(jcmd_opt_t, rcps),
        .set = jcmd_opt_set_jsons,
        .doc = doc_recipient,
        .def = "{}",
    },
    {
        .opt = { "key", required_argument, .val = 'k' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = jcmd_opt_set_jwks,
        .doc = jcmd_doc_key,
    },
    {
        .opt = { "password", no_argument, .val = 'p' },
        .off = offsetof(jcmd_opt_t, keys),
        .set = opt_set_password,
        .doc = doc_password,
    },
    {
        .opt = { "output", required_argument, .val = 'o' },
        .off = offsetof(jcmd_opt_t, io.output),
        .set = jcmd_opt_set_ofile,
        .doc = jcmd_jwe_doc_output,
        .def = "-",
    },
    {
        .opt = { "detach", required_argument, .val = 'O' },
        .off = offsetof(jcmd_opt_t, io.detach),
        .set = jcmd_opt_set_ofile,
        .doc = jcmd_jwe_doc_detach,
    },
    {
        .opt = { "compact", no_argument, .val = 'c' },
        .off = offsetof(jcmd_opt_t, io.compact),
        .set = jcmd_opt_set_flag,
        .doc = jcmd_jwe_doc_compact,
    },
    {}
};

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    jcmd_opt_io_cleanup(&opt->io);
    json_decrefp(&opt->keys);
    json_decrefp(&opt->rcps);
}

static bool
opt_validate(jcmd_opt_t *opt)
{
    size_t nkeys = json_array_size(opt->keys);

    if (nkeys == 0) {
        fprintf(stderr, "Must specify a JWK or password!\n");
        return false;
    } else if (nkeys > 1 && opt->io.compact) {
        fprintf(stderr, "Requested compact format with >1 recipient!\n");
        return false;
    }

    if (!opt->io.detached) {
        fprintf(stderr, "Must specify detached input!\n");
        return false;
    }

    if (json_array_remove(opt->rcps, 0) < 0)
        return false;

    if (json_array_size(opt->keys) < json_array_size(opt->rcps)) {
        fprintf(stderr, "Specified more recipients than keys!\n");
        return false;
    }

    while (json_array_size(opt->rcps) < json_array_size(opt->keys)) {
        if (json_array_append_new(opt->rcps, json_object()) < 0)
            return false;
    }

    return true;
}

static json_t *
wrap(jcmd_opt_t *opt)
{
    json_auto_t *cek = json_object();

    for (size_t i = 0; i < json_array_size(opt->keys); i++) {
        json_auto_t *jwk = json_incref(json_array_get(opt->keys, i));
        json_t *rcp = json_array_get(opt->rcps, i);

        if (json_is_null(jwk)) {
            json_decref(jwk);
            jwk = prompt();
        }

        if (!jose_jwe_enc_jwk(NULL, opt->io.obj, rcp, jwk, cek)) {
            fprintf(stderr, "Wrapping failed!\n");
            return NULL;
        }
    }

    if (opt->io.compact) {
        json_t *jh = NULL;

        jh = jose_jwe_hdr(opt->io.obj, opt->io.obj);
        if (!jh)
            return NULL;

        if (json_object_set_new(opt->io.obj, "protected", jh) < 0)
            return NULL;

        if (json_object_get(opt->io.obj, "unprotected") &&
            json_object_del(opt->io.obj, "unprotected") < 0)
            return NULL;

        if (json_object_get(opt->io.obj, "header") &&
            json_object_del(opt->io.obj, "header") < 0)
            return NULL;
    }

    return json_incref(cek);
}

static int
jcmd_jwe_enc(int argc, char *argv[])
{
    jcmd_opt_auto_t opt = { .io.fields = jcmd_jwe_fields };
    jose_io_auto_t *out = NULL;
    jose_io_auto_t *enc = NULL;
    json_auto_t *cek = NULL;

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;

    if (!opt_validate(&opt))
        return EXIT_FAILURE;

    cek = wrap(&opt);
    if (!cek)
        return EXIT_FAILURE;

    out = jose_io_file(NULL, opt.io.detach ? opt.io.detach : opt.io.output);
    if (!out)
        return EXIT_FAILURE;

    if (!opt.io.detach) {
        jose_io_auto_t *b64 = NULL;

        b64 = jose_b64_enc_io(out);
        if (!b64)
            return EXIT_FAILURE;

        jose_io_auto(&out);
        out = jose_io_incref(b64);
    }

    enc = jose_jwe_enc_cek_io(NULL, opt.io.obj, cek, out);
    if (!enc)
        return EXIT_FAILURE;

    if (!opt.io.detached) {
        jose_io_auto_t *b64 = NULL;

        b64 = jose_b64_dec_io(enc);
        if (!b64)
            return EXIT_FAILURE;

        jose_io_auto(&enc);
        enc = jose_io_incref(b64);
    }

    if (opt.io.compact) {
        for (size_t i = 0; i < 3; i++) {
            const char *k = jcmd_jwe_fields[i].name;
            const char *v = NULL;

            if (json_unpack(opt.io.obj, "{s?s}", k, &v) < 0)
                return EXIT_FAILURE;

            fprintf(opt.io.output, "%s.", v ? v : "");
        }
    } else {
        fprintf(opt.io.output, "{");
        if (!opt.io.detach)
            fprintf(opt.io.output, "\"ciphertext\":\"");
    }

    if (opt.io.detached || opt.io.input) {
        FILE *f = opt.io.detached ? opt.io.detached : opt.io.input;

        for (int c = fgetc(f); c != EOF; c = fgetc(f)) {
            uint8_t b = c;

            if (!opt.io.detached && b == '.')
                break;

            if (!enc->feed(enc, &b, sizeof(b)))
                return EXIT_FAILURE;
        }

        for (int c = 0; opt.io.detached && opt.io.input && c != EOF && c != '.'; )
            c = fgetc(opt.io.input);
    } else {
        const char *ct = NULL;
        size_t ctl = 0;

        if (json_unpack(opt.io.obj, "{s:s%}", "ciphertext", &ct, &ctl) < 0)
            return EXIT_FAILURE;

        if (!enc->feed(enc, ct, ctl))
            return EXIT_FAILURE;
    }

    if (opt.io.input) {
        if (json_object_set_new(opt.io.obj, "tag",
                                jcmd_compact_field(opt.io.input)) < 0) {
            fprintf(stderr, "Error reading last compact field!\n");
            return EXIT_FAILURE;
        }
    }

    if (!enc->done(enc))
        return EXIT_FAILURE;

    if (opt.io.compact) {
        const char *v = NULL;

        if (json_unpack(opt.io.obj, "{s:s}", "tag", &v) < 0) {
            fprintf(stderr, "Missing tag parameter!\n");
            return false;
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

JCMD_REGISTER(SUMMARY, jcmd_jwe_enc, "jwe", "enc")
