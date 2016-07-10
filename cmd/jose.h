/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/jwe.h>
#include <getopt.h>

void *
jcmd_load_stdin(size_t *len);

void *
jcmd_load_file(const char *filename, size_t *len);

json_t *
jcmd_load(const char *file, const char *raw,
          json_t *(*conv)(const char *));

bool
jcmd_dump_file(const char *filename, const uint8_t buf[], size_t len);

bool
jcmd_dump(const json_t *json, const char *filename,
          char *(*conv)(const json_t *));

int
jcmd_gen(int argc, char *argv[]);

int
jcmd_pub(int argc, char *argv[]);

int
jcmd_sig(int argc, char *argv[]);

int
jcmd_ver(int argc, char *argv[]);

int
jcmd_enc(int argc, char *argv[]);

int
jcmd_dec(int argc, char *argv[]);
