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

static void *
load_stdin(size_t *len)
{
    uint8_t *buf = NULL;

    if (!len)
        return NULL;

    *len = 0;

    for (size_t r = 512; r == 512; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(buf, *len + 512 + 1);
        if (!tmp) {
            if (buf)
                memset(buf, 0, *len);
            free(buf);
            return NULL;
        }

        buf = tmp;
        r = fread(&buf[*len], 1, 512, stdin);
        *len += r;
        buf[*len] = 0;
    }

    return buf;
}

static void *
load_file(const char *filename, size_t *len)
{
    struct stat st = {};
    uint8_t *buf = NULL;
    FILE *file = NULL;

    if (!filename || !len)
        return NULL;

    if (stat(filename, &st) != 0)
        return NULL;

    file = fopen(filename, "r");
    if (!file)
        return NULL;

    buf = malloc(st.st_size + 1);
    if (!buf) {
        fclose(file);
        return NULL;
    }

    if (fread(buf, st.st_size, 1, file) != 1) {
        if (buf)
            memset(buf, 0, st.st_size);
        fclose(file);
        free(buf);
        return NULL;
    }
    fclose(file);

    *len = st.st_size;
    buf[*len] = 0;
    return buf;
}

void *
jcmd_load_data(const char *file, size_t *len)
{
    if (!file)
        return NULL;

    if (strcmp(file, "-") == 0)
        return load_stdin(len);

    return load_file(file, len);
}

json_t *
jcmd_load_json(const char *file, const char *raw,
               json_t *(*conv)(const char *))
{
    json_t *out = NULL;
    char *buf = NULL;
    size_t len = 0;

    if (raw)
        len = strlen(raw);

    if (file) {
        buf = jcmd_load_data(file, &len);
        raw = buf ? buf : raw;
    }

    out = json_loadb(raw, len, JSON_DECODE_ANY, NULL);
    if (!out && conv)
        out = conv(raw);

    if (buf)
        memset(buf, 0, len);
    free(buf);
    return out;
}

bool
jcmd_dump_data(const char *filename, const uint8_t buf[], size_t len)
{
    FILE *file = NULL;
    bool ret = false;

    if (!filename)
        return false;

    if (strcmp(filename, "-") != 0)
        file = fopen(filename, "w");

    ret = fwrite(buf, 1, len, file ? file : stdout) == len;

    if (file)
        fclose(file);

    return ret;
}

bool
jcmd_dump_json(const json_t *json, const char *filename,
               char *(*conv)(const json_t *))
{
    FILE *file = NULL;
    char *comp = NULL;
    bool ret = false;

    if (filename && strcmp(filename, "-") != 0) {
        file = fopen(filename, "w");
        if (!file)
            return false;
    }

    if (conv) {
        comp = conv(json);
        if (!comp)
            goto egress;

        if (fwrite(comp, strlen(comp), 1, file ? file : stdout) != 1)
            goto egress;
    } else {
        if (json_dumpf(json, file ? file : stdout,
                       JSON_SORT_KEYS | JSON_COMPACT) == -1)
            goto egress;
    }

    if (!file)
        fprintf(stdout, "\n");

    ret = true;

egress:
    if (file)
        fclose(file);
    free(comp);
    return ret;
}

bool
jcmd_jwks_extend(json_t *jwks, json_t *jwk_or_jwkset)
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

int
main(int argc, char *argv[])
{
    static const struct {
        const char *cmd;
        int (*func)(int argc, char *argv[]);
    } table[] = {
        { "gen", jcmd_gen },
        { "pub", jcmd_pub },
        { "thp", jcmd_thp },
        { "use", jcmd_use },
        { "exc", jcmd_exc },
        { "sig", jcmd_sig },
        { "ver", jcmd_ver },
        { "enc", jcmd_enc },
        { "dec", jcmd_dec },
        { "sup", jcmd_sup },
        {}
    };

    const char *cmd = NULL;

    if (argc >= 2) {
        char argv0[strlen(argv[0]) + strlen(argv[1]) + 2];
        strcpy(argv0, argv[0]);
        strcat(argv0, " ");
        strcat(argv0, argv[1]);
        cmd = argv[1];
        argv[1] = argv0;

        for (size_t i = 0; table[i].cmd; i++) {
            if (strcmp(cmd, table[i].cmd) == 0)
                return table[i].func(argc - 1, argv + 1);
        }
    }

    fprintf(stderr,
"Usage: jose COMMAND [OPTIONS] [ARGUMENTS]\n"
"\n"
"\n  jose " GEN_USE
"\n  jose " PUB_USE
"\n  jose " THP_USE
"\n  jose " USE_USE
"\n  jose " EXC_USE
"\n  jose " SIG_USE
"\n  jose " VER_USE
"\n  jose " ENC_USE
"\n  jose " DEC_USE
"\n  jose " SUP_USE
"\n");
    return EXIT_FAILURE;
}
