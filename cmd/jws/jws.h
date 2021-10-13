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

#pragma once

#include "../jose.h"
#include <string.h>

static const jcmd_field_t jcmd_jws_fields[] = {
    { .name = "protected", .mult = "signatures" },
    { .name = "payload" },
    { .name = "signature", .mult = "signatures" },
    {}
};

static const jcmd_doc_t jcmd_jws_doc_input[] = {
    { .arg = "JSON", .doc="Parse JWS from JSON" },
    { .arg = "FILE", .doc="Read JWS from FILE" },
    { .arg = "-",    .doc="Read JWS from standard input" },
    {}
};

static const jcmd_doc_t jcmd_jws_doc_detached[] = {
    { .arg = "FILE", .doc="Read decoded payload from FILE" },
    { .arg = "-",    .doc="Read decoded payload from standard input" },
    {}
};

static const jcmd_doc_t jcmd_jws_doc_output[] = {
    { .arg = "FILE", .doc="Write JWS to FILE" },
    { .arg = "-",    .doc="Write JWS to stdout (default)" },
    {}
};

static const jcmd_doc_t jcmd_jws_doc_detach[] = {
    { .arg = "FILE", .doc="Detach payload and decode to FILE" },
    { .arg = "-",    .doc="Detach payload and decode to standard output" },
    {}
};

static const jcmd_doc_t jcmd_jws_doc_compact[] = {
    { .doc="Output JWS using compact serialization" },
    {}
};

static void
jcmd_jws_ios_auto(jose_io_t ***iosp)
{
    jose_io_t **ios = *iosp;

    for (size_t i = 0; ios && ios[i]; i++)
        jose_io_auto(&ios[i]);
}

static jose_io_t *
jcmd_jws_prep_io(jcmd_opt_io_t *opt, jose_io_t *io)
{
    jose_io_t __attribute__((cleanup(jcmd_jws_ios_auto))) **ios = NULL;
    size_t i = 0;

    ios = alloca(sizeof(*ios) * 3);
    memset(ios, 0, sizeof(*ios) * 3);

    if (io)
        ios[i++] = io;

    if (opt->detach) {
        jose_io_auto_t *b64 = NULL;

        ios[i] = jose_io_file(NULL, opt->detach);
        if (!ios[i])
            return NULL;

        b64 = jose_b64_dec_io(ios[i]);
        if (!b64)
            return NULL;

        jose_io_auto(&ios[i]);
        ios[i] = jose_io_incref(b64);
    } else if (opt->output) {
        ios[i] = jose_io_file(NULL, opt->output);
        if (!ios[i])
            return NULL;
    }

    for (i = 0; opt->detached && ios[i]; i++) {
        jose_io_auto_t *b64 = NULL;

        b64 = jose_b64_enc_io(ios[i]);
        if (!b64)
            return NULL;

        jose_io_decref(ios[i]);
        ios[i] = jose_io_incref(b64);
    }

    return jose_io_multiplex(NULL, ios, true);
}
