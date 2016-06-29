/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../b64.h"
#include "../jwk.h"
#include "../jws.h"
#include "../jwe.h"

json_t *
load_compact(FILE *file, json_t *(*conv)(const char *));

int
jose_generate(int argc, char *argv[]);

int
jose_publicize(int argc, char *argv[]);

int
jose_sign(int argc, char *argv[]);

int
jose_verify(int argc, char *argv[]);

int
jose_encrypt(int argc, char *argv[]);

int
jose_decrypt(int argc, char *argv[]);
