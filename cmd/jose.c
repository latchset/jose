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

#include <cmd/jose.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#define MAXBUFLEN 1024
#define RQARG required_argument
#define NOARG no_argument

static jcmd_t *cmds;

static bool
is_json_object_file(FILE *file)
{
    int c;

    do {
        c = fgetc(file);
    } while (isspace(c));

    return ungetc(c, file) == '{';
}

static bool
jwks_extend(json_t *jwks, json_t *jwk_or_jwkset)
{
    json_t *keys = json_object_get(jwk_or_jwkset, "keys");
    size_t size = json_array_size(keys);

    if (!json_is_array(keys))
        return json_array_append_new(jwks, jwk_or_jwkset) == 0;

    for (size_t i = 0; i < size; i++) {
        if (json_array_append(jwks, json_array_get(keys, i)) == -1) {
            json_decref(jwk_or_jwkset);
            return false;
        }
    }

    json_decref(jwk_or_jwkset);
    return size > 0;
}

void
jcmd_push(jcmd_t *cmd)
{
    cmd->next = cmds;
    cmds = cmd;
}

bool
jcmd_opt_parse(int argc, char *argv[], const jcmd_cfg_t *cfgs, void *vopt,
               const char *prefix)
{
    size_t ncfgs = 0;
    int maxa = 0;
    int maxl = 0;

    for (; cfgs[ncfgs].doc; ncfgs++) {
        const jcmd_cfg_t *cfg = &cfgs[ncfgs];

        for (size_t i = 0; cfg->doc[i].doc; i++) {
            int len = 0;

            if (!cfg->doc[i].arg)
                continue;

            len = strlen(cfg->doc[i].arg);
            if (len > maxa)
                maxa = len;

            len = strlen(cfg->opt.name) + len;
            if (len > maxl)
                maxl = len;
        }

        if (cfg->def) {
            uint8_t *buf = vopt;
            if (!cfg->set(cfg, &buf[cfg->off], cfg->def)) {
                fprintf(stderr, "Invalid default value for %s!\n", cfg->opt.name);
                return false;
            }
        }
    }

    char sopts[ncfgs * 3 + 3];
    struct option lopts[ncfgs + 3];
    memset(lopts, 0, sizeof(lopts));

    lopts[0].has_arg = no_argument;
    lopts[0].name = "help";
    lopts[0].val = 'h';
    lopts[1].has_arg = no_argument;
    lopts[1].name = "version";
    lopts[1].val = 'v';
    strcpy(sopts, "hv");

    for (size_t i = 0; i < ncfgs; i++) {
        strncat(sopts, &(char) { cfgs[i].opt.val }, 1);
        lopts[i + 2] = cfgs[i].opt;
        switch (cfgs[i].opt.has_arg) {
        case optional_argument: strcat(sopts, ":"); /* fallthrough */
        case required_argument: strcat(sopts, ":"); /* fallthrough */
        default: break;
        }
    }

    for (int c; (c = getopt_long(argc, argv, sopts, lopts, NULL)) >= 0; ) {
        bool found = false;

        for (size_t i = 0; i < ncfgs; i++) {
            uint8_t *buf = vopt;
            if (cfgs[i].opt.val == c) {
                found = true;

                if (!cfgs[i].set(&cfgs[i], &buf[cfgs[i].off], optarg)) {
                    fprintf(stderr, "Invalid %s!\n", cfgs[i].opt.name);
                    goto usage;
                }

                break;
            }
        }

        if (!found) {
            switch (c) {
            case 'h': goto usage;
            case 'v': fprintf(stderr, "José %d\n", JOSE_VERSION); return false;
            default:  fprintf(stderr, "Unknown option: %c!\n", c); goto usage;
            }
        }
    }

    return true;

usage:
    fprintf(stderr, "Usage: %s\n\n", prefix);

    for (size_t i = 0; i < ncfgs; i++) {
        for (size_t j = 0; cfgs[i].doc[j].doc; j++) {
            const char *n = cfgs[i].opt.name;
            const char  v = cfgs[i].opt.val;
            const char *a = cfgs[i].doc[j].arg;
            const char d = a ? '=' : ' ';
            a = a ? a : "";
            fprintf(stderr, "  -%c %-*s --%s%c%-*s  %s\n",
                    v, maxa, a,
                    n, d, maxl - (int) strlen(n), a,
                    cfgs[i].doc[j].doc);
        }

        if (cfgs[i].def) {
            fprintf(stderr, "%*sDefault: \"%s\"\n",
                    maxa + maxl + 11, "", cfgs[i].def);
        }

        fprintf(stderr, "\n");
    }

    return false;
}

static bool
valid_b64(const char *b64, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (b64[i] != 0 && !strchr(JOSE_B64_MAP, b64[i]))
            return false;
    }

    return true;
}

static json_t *
parse_compact(jcmd_opt_io_t *io, const char *arg)
{
    json_auto_t *tmp = json_object();
    size_t i = 0;

    for (size_t j = 0; io->fields[j].name; j++) {
        const char *enc = strchr(&arg[i], '.');
        size_t len = strlen(&arg[i]);

        if (enc)
            len = enc - &arg[i];
        else if (io->fields[j + 1].name)
            return NULL;

        if (!valid_b64(&arg[i], len))
            return NULL;

        if (json_object_set_new(tmp, io->fields[j].name,
                                json_stringn(&arg[i], len)) < 0)
            return NULL;

        i += len + 1;
    }

    return json_incref(tmp);
}

bool
jcmd_opt_io_set_input(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    jcmd_opt_io_t *io = vopt;

    jcmd_file_cleanup(&io->input);
    json_decrefp(&io->obj);

    io->obj = json_loads(arg, 0, NULL);
    if (!io->obj)
        io->obj = parse_compact(io, arg);
    if (!io->obj) {
        if (strcmp("-", arg) == 0)
            io->input = stdin;
        else
            io->input = fopen(arg, "r");
        if (!io->input)
            return false;

        if (is_json_object_file(io->input)) {
            io->obj = json_loadf(io->input, JSON_DISABLE_EOF_CHECK, NULL);
            jcmd_file_cleanup(&io->input);
        } else {
            io->obj = json_object();
            for (size_t i = 0;
                 io->fields[i].name &&
                 io->fields[i + 1].name &&
                 io->fields[i + 2].name; i++) {
                if (json_object_set_new(io->obj, io->fields[i].name,
                                        jcmd_compact_field(io->input)) < 0)
                    return false;
            }
        }
    }

    return json_is_object(io->obj);
}

bool
jcmd_opt_set_ifile(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    FILE **file = vopt;
    jcmd_file_cleanup(file);
    if (strcmp("-", arg) == 0)
        *file = stdin;
    else
        *file = fopen(arg, "r");

    return *file;
}

bool
jcmd_opt_set_ofile(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    FILE **file = vopt;
    jcmd_file_cleanup(file);
    if (strcmp("-", arg) == 0)
        *file = stdout;
    else
        *file = fopen(arg, "w");
    return *file;
}

bool
jcmd_opt_set_jsons(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    json_auto_t *tmp = NULL;
    json_t **json = vopt;

    if (!jcmd_opt_set_json(cfg, &tmp, arg))
        return false;

    if (!*json)
        *json = json_array();

    return json_array_append(*json, tmp) >= 0;
}

bool
jcmd_opt_set_json(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    const int flags = JSON_DISABLE_EOF_CHECK | JSON_DECODE_ANY;
    json_t **json = vopt;

    json_decrefp(json);

    *json = json_loads(arg, flags, NULL);
    if (!*json) {
        if (strcmp(arg, "-") == 0) {
            *json = json_loadf(stdin, flags, NULL);
        } else {
            FILE_AUTO *file = fopen(arg, "r");
            *json = json_loadf(file, flags, NULL);
        }
    }

    return *json;
}

bool
jcmd_opt_set_jwkt(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    const int flags = JSON_DISABLE_EOF_CHECK | JSON_DECODE_ANY;
    json_auto_t *tmp = NULL;
    json_t **jwks = vopt;

    if (!*jwks)
        *jwks = json_array();

    tmp = json_loads(arg, flags, NULL);
    if (!tmp) {
        if (strcmp(arg, "-") == 0) {
            tmp = json_loadf(stdin, flags, NULL);
        } else {
            FILE_AUTO *file = fopen(arg, "r");
            tmp = json_loadf(file, flags, NULL);
        }
    }

    switch (json_typeof(tmp)) {
    case JSON_OBJECT:
    case JSON_STRING:
        return jwks_extend(*jwks, json_incref(tmp));
    default:
        return false;
    }
}

bool
jcmd_opt_set_jwks(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    const int flags = JSON_DISABLE_EOF_CHECK | JSON_DECODE_ANY;
    json_auto_t *tmp = NULL;
    json_t **jwks = vopt;

    if (!*jwks)
        *jwks = json_array();

    if (strcmp(arg, "-") == 0) {
        tmp = json_loadf(stdin, flags, NULL);
    } else {
        FILE_AUTO *file = fopen(arg, "r");
        tmp = json_loadf(file, flags, NULL);
    }

    switch (tmp ? json_typeof(tmp) : JSON_INTEGER) {
    case JSON_OBJECT:
    case JSON_STRING:
        return jwks_extend(*jwks, json_incref(tmp));
    default:
        return false;
    }
}

bool
jcmd_opt_set_flag(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    bool *flag = vopt;
    return *flag = true;
}

void
jcmd_opt_io_cleanup(jcmd_opt_io_t *io)
{
    if (!io)
        return;

    jcmd_file_cleanup(&io->detached);
    jcmd_file_cleanup(&io->detach);
    jcmd_file_cleanup(&io->output);
    jcmd_file_cleanup(&io->input);
    json_decrefp(&io->obj);
}

json_t *
jcmd_compact_field(FILE *file)
{
    json_t *str = NULL;
    char *buf = NULL;
    size_t used = 0;
    size_t size = 0;

    for (int c = fgetc(file); c != EOF && c != '.'; c = fgetc(file)) {
        if (used >= size) {
            char *tmp = NULL;

            size += 4096;
            tmp = realloc(buf, size);
            if (!tmp)
                goto error;

            buf = tmp;
        }

        buf[used++] = c;
    }

    str = json_stringn(buf ? buf : "", buf ? used : 0);

error:
    free(buf);
    return str;
}

void
jcmd_file_cleanup(FILE **file)
{
    if (file && *file) {
        if (*file != stdin && *file != stdout)
            fclose(*file);
        *file = NULL;
    }
}

static int
nnames(const jcmd_t *cmd)
{
    int n = 0;

    while (cmd->names[n])
        n++;

    return n;
}

static int
cmp(const void *a, const void *b)
{
    const jcmd_t * const *ap = a;
    const jcmd_t * const *bp = b;
    int c = 0;

    c = nnames(*ap) - nnames(*bp);

    for (size_t i = 0; c == 0; i++) {
        const char *an = (*ap)->names[i];
        const char *bn = (*bp)->names[i];

        if (!an && !bn)
            return 0;

        if (!an && bn)
            return -1;

        if (an && !bn)
            return 1;

        c = strcmp(an, bn);
    }

    return c;
}

int
main(int argc, char *argv[])
{
    const char *last = NULL;
    char full[40] = {};
    size_t len = 0;

    for (int i = 0; i < argc; i++)
        len += strlen(argv[i]) + 1;

    char cmd[len];

    len = 0;
    for (const jcmd_t *c = cmds; c; c = c->next) {
        strcpy(cmd, "jose");
        len++;

        for (int i = 1; i < argc && c->names[i - 1]; i++) {
            const char *name = c->names[i - 1];

            if (strcmp(argv[i], name) != 0)
                break;

            if (!c->names[i]) {
                argv[--i] = cmd;
                return c->func(argc - i, argv + i);
            }

            strcat(cmd, " ");
            strcat(cmd, name);
        }
    }

    const jcmd_t *all[len];

    for (const jcmd_t *c = cmds; c; c = c->next)
        all[--len] = c;

    qsort(all, sizeof(all) / sizeof(*all), sizeof(*all), cmp);

    fprintf(stderr, "Usage: jose COMMAND [OPTIONS] [ARGUMENTS]\n\n");
    fprintf(stderr, "Commands:\n");
    for (size_t i = 0; i < sizeof(all) / sizeof(*all); i++) {
        if (!(last && strcmp(all[i]->names[0], last) == 0))
            fprintf(stderr, "\n");

        strcpy(full, "jose");
        for (size_t j = 0; all[i]->names[j]; j++) {
            snprintf(full + strlen(full),
                     sizeof(full) - strlen(full) - 1,
                     " %s", all[i]->names[j]);
        }

        fprintf(stderr, "  %-13s %s\n", full, all[i]->desc);
        last = all[i]->names[0];
    }

    fprintf(stderr, "\n");
    return EXIT_FAILURE;
}
