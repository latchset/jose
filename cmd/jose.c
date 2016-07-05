/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <cmd/jose.h>

#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

void *
jcmd_load_stdin(size_t *len)
{
    uint8_t *buf = NULL;

    if (!len)
        return NULL;

    *len = 0;

    for (size_t r = 512; r == 512; ) {
        uint8_t *tmp = NULL;

        tmp = realloc(buf, *len + 512);
        if (!tmp) {
            free(buf);
            return NULL;
        }

        buf = tmp;
        r = fread(&buf[*len], 1, 512, stdin);
        *len += r;
    }

    return buf;
}

void *
jcmd_load_file(const char *filename, size_t *len)
{
    struct stat st = {};
    FILE *file = NULL;
    uint8_t *buf = NULL;

    if (!filename || !len)
        return NULL;

    if (stat(filename, &st) != 0)
        return NULL;

    file = fopen(filename, "r");
    if (!file)
        return NULL;

    buf = malloc(st.st_size);
    if (!buf) {
        fclose(file);
        return NULL;
    }

    if (fread(buf, st.st_size, 1, file) != 1) {
        fclose(file);
        free(buf);
        return NULL;
    }
    fclose(file);

    *len = st.st_size;
    return buf;
}

json_t *
jcmd_load(const char *file, const char *raw,
          json_t *(*conv)(const char *))
{
    json_t *out = NULL;
    char *buf = NULL;
    size_t len = 0;

    buf = jcmd_load_file(file, &len);
    if (buf)
        raw = buf;
    else if (raw)
        len = strlen(raw);
    else
        raw = buf = jcmd_load_stdin(&len);

    out = json_loadb(raw, len, 0, NULL);
    if (!out && conv)
        out = conv(raw);

    free(buf);
    return out;
}

bool
jcmd_dump_file(const char *filename, const uint8_t buf[], size_t len)
{
    FILE *file = NULL;
    bool ret = false;

    if (filename)
        file = fopen(filename, "w");

    ret = fwrite(buf, 1, len, file ? file : stdout) == len;

    if (file)
        fclose(file);

    return ret;
}

bool
jcmd_dump(const json_t *json, const char *filename,
          char *(*conv)(const json_t *))
{
    FILE *file = NULL;
    char *comp = NULL;
    bool ret = false;

    if (filename) {
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
        if (json_dumpf(json, file ? file : stdout, JSON_SORT_KEYS) == -1)
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

int
main(int argc, char *argv[])
{
    static const struct {
        const char *cmd;
        int (*func)(int argc, char *argv[]);
    } table[] = {
        { "gen", jcmd_gen },
        { "pub", jcmd_pub },
        { "sig", jcmd_sig },
        { "ver", jcmd_ver },
        { "enc", jcmd_enc },
        { "dec", jcmd_dec },
        {}
    };

    const char *cmd = NULL;

    RAND_poll();

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
"jose gen           [-o FILE] [-t TMPL]\n"
"jose pub [-i FILE] [-o FILE] [-t TYPE ...]\n"
"jose sig [-i FILE] [-o FILE] [-t TMPL] [-s SIGT ...] [-c]       JWK ...\n"
"jose ver [-i FILE] [-o FILE]                         [-a]       JWK ...\n"
"jose enc [-i FILE] [-o FILE] [-t TMPL] [-r RCPT ...] [-c] [-p]  JWK ...\n"
"jose dec [-i FILE] [-o FILE]                              [-n] [JWK ...]\n"
"\n");
    return EXIT_FAILURE;
}
