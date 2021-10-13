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

#pragma once

#include <jose/jose.h>
#include <getopt.h>

#define __JCMD_AUTO(t) t ## _t __attribute__((cleanup(t ## _cleanup)))
#define jcmd_opt_key_auto_t __JCMD_AUTO(jcmd_opt_key)
#define jcmd_opt_io_auto_t  __JCMD_AUTO(jcmd_opt_io)
#define jcmd_opt_auto_t     __JCMD_AUTO(jcmd_opt)
#define FILE_AUTO      FILE __attribute__((cleanup(jcmd_file_cleanup)))

#define JCMD_REGISTER(summary, function, ...)               \
    static void __attribute__((constructor))                \
    jcmd_ ## function ## _register(void)                    \
    {                                                       \
        static const char *names[] = { __VA_ARGS__, NULL }; \
        static jcmd_t cmd = {                               \
            .names = names,                                 \
            .func = function,                               \
            .desc = summary                                 \
        };                                                  \
        jcmd_push(&cmd);                                    \
    }

typedef struct jcmd_cfg jcmd_cfg_t;
typedef bool jcmd_set_t(const jcmd_cfg_t *cfg, void *vopt, const char *arg);

typedef struct {
    const char *arg;
    const char *doc;
} jcmd_doc_t;

struct jcmd_cfg {
    const jcmd_doc_t *doc;
    struct option opt;
    const char *def;
    jcmd_set_t *set;
    off_t off;
};

typedef struct {
    const char *name;
    const char *mult;
} jcmd_field_t;

typedef struct {
    const jcmd_field_t *fields;
    FILE *detached;
    bool  compact;
    FILE *detach;
    FILE *output;
    FILE *input;
    json_t *obj;
} jcmd_opt_io_t;

typedef struct jcmd jcmd_t;
struct jcmd {
    const jcmd_t *next;
    const char *const *names;
    int (*func)(int argc, char *argv[]);
    const char *desc;
};

static const jcmd_doc_t jcmd_doc_key[] = {
    { .arg = "FILE", .doc="Read JWK(Set) from FILE" },
    { .arg = "-",    .doc="Read JWK(Set) from standard input" },
    {}
};

void
jcmd_push(jcmd_t *cmd);

bool
jcmd_opt_parse(int argc, char *argv[], const jcmd_cfg_t *cfgs, void *arg,
               const char *prefix);

jcmd_set_t jcmd_opt_io_set_input; /* Takes jcmd_opt_io_t* */
jcmd_set_t jcmd_opt_set_ifile;    /* Takes FILE** */
jcmd_set_t jcmd_opt_set_ofile;    /* Takes FILE** */
jcmd_set_t jcmd_opt_set_jsons;    /* Takes json_t** */
jcmd_set_t jcmd_opt_set_json;     /* Takes json_t** */
jcmd_set_t jcmd_opt_set_jwkt;     /* Takes json_t** */
jcmd_set_t jcmd_opt_set_jwks;     /* Takes json_t** */
jcmd_set_t jcmd_opt_set_flag;     /* Takes bool* */

void
jcmd_opt_io_cleanup(jcmd_opt_io_t *io);

void
jcmd_opt_key_cleanup(jcmd_opt_io_t *io);

json_t *
jcmd_compact_field(FILE *file);

void
jcmd_file_cleanup(FILE **file);
