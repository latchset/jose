/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jose.h"
#include <jose/openssl.h>
#include <string.h>
#include <unistd.h>
#define SUMMARY "Generates passphrases using PBKDF2"
typedef struct {
    unsigned char *salt;
    unsigned char *hash;
    char *iter;
    FILE *input;
} jcmd_opt_t;

static const char *prefix = "jose pbkdf2 -i BIN [-I ITER] [-s SALT] [-a ALG]\n\n";

static const jcmd_doc_t doc_input[] = {
    { .arg = "FILE", .doc="Read data from FILE" },
    { .arg = "-",    .doc="Read data from standard input" },
    {}
};

static const jcmd_doc_t doc_iter[] = {
    { .arg = "ITER", .doc="Number of PBKDF2 iterations" },
    {}
};

static const jcmd_doc_t doc_salt[] = {
    { .arg = "SALT", .doc="Specify salt as input to PBKDF2" },
    {}
};
static const jcmd_doc_t doc_hash[] = {
    { .arg = "ALG", .doc="Specify hash algorithm ALG for PBKDF2" },
    {}
};
static bool
jcmd_opt_set_str(const jcmd_cfg_t *cfg, void *vopt, const char *arg)
{
    const char **find = vopt;
    *find = arg;
    return true;
}

static void
jcmd_opt_cleanup(jcmd_opt_t *opt)
{
    ;
}

static const jcmd_cfg_t cfgs[] = {
    {
        .opt = { "input", required_argument, .val = 'i' },
        .off = offsetof(jcmd_opt_t, input),
        .set = jcmd_opt_set_ifile,
        .doc = doc_input,
        .def = "-",
    },
    {
        .opt = { "iteration_count", required_argument, .val = 'I'},
        .off = offsetof(jcmd_opt_t, iter),
        .set = jcmd_opt_set_str,
        .doc = doc_iter,
        .def = "4096",
    },
    {
        .opt = { "salt", required_argument, .val = 's'},
        .off = offsetof(jcmd_opt_t, salt),
        .set = jcmd_opt_set_str,
        .doc = doc_salt,
    },
    {
        .opt = { "hash", required_argument, .val = 'a'},
        .off = offsetof(jcmd_opt_t, hash),
        .set = jcmd_opt_set_str,
        .doc = doc_hash,
        .def = "S256",
    },
    {}
};

static size_t
str2enum(const char *str, ...)
{
    size_t i = 0;
    va_list ap;

    va_start(ap, str);

    for (const char *v = NULL; (v = va_arg(ap, const char *)); i++) {
        if (str && strcmp(str, v) == 0) {
            va_end(ap);
            return i;
        }
    }

    va_end(ap);
    return SIZE_MAX;
}

static int
jcmd_pbkdf2(int argc, char *argv[])
{
    char pass[4096] = { 0 };
    jcmd_opt_auto_t opt = {};

    if (!jcmd_opt_parse(argc, argv, cfgs, &opt, prefix))
        return EXIT_FAILURE;
    uint64_t iter = strtoul(opt.iter,NULL,10);
    size_t i = 0;

    size_t ret = 0;
    const EVP_MD *md=NULL;
    if (! opt.salt) {
        opt.salt = (unsigned char*) "NaCL is the chemical formula for salt!";
    }
    switch (str2enum((char*)opt.hash, "S512", "S384", "S256", "S224", "S1", NULL)) {
    case 0: md = EVP_sha512(); break;
    case 1: md = EVP_sha384(); break;
    case 2: md = EVP_sha256(); break;
    case 3: md = EVP_sha224(); break;
    case 4: md = EVP_sha1();   break;
    }
    unsigned char result[EVP_MD_size(md)];

    if (!md) {
        fprintf(stderr, "Couldn't find hash alg: '%s'\n", opt.hash);
        return EXIT_FAILURE;
    }

    while(!feof(opt.input)) {
        ret = fread(&pass[i], 1, 1, opt.input);
        i+=ret;
        if (ferror(opt.input))
            return EXIT_FAILURE;

    }
    PKCS5_PBKDF2_HMAC (pass, sizeof(pass) -1, opt.salt, sizeof(opt.salt)-1, iter, md, EVP_MD_size(md), result);
    for (ssize_t j = 0; j < EVP_MD_size(md); j++) {
        fprintf(stdout, "%c", result[j]);
    }

    return 0;
}

JCMD_REGISTER(SUMMARY, jcmd_pbkdf2, "pbkdf2")
