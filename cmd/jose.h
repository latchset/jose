/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/jwe.h>
#include <getopt.h>

#define GEN_USE \
    "gen -t TMPL ... [-o JWK(Set)]"

#define PUB_USE \
    "pub -i JWK(Set) [-o JWK(Set)]"

#define THP_USE \
    "thp -i JWK(Set) [-H HASH] [-o THMB]"

#define SIG_USE \
    "sig -i PLD [-t TMPL] [-s SIGT ...] -k JWK(Set) ... [-o JWS] [-c] [-d]"

#define VER_USE \
    "ver -i JWS [-d DTCH] -k JWK(Set) ... [-a] [-o PLD]"

#define ENC_USE \
    "enc -i PLD [-t TMPL] [-r RCPT ...] [-p ...] -k JWK(Set) ... [-c] [-o JWE]"

#define DEC_USE \
    "dec -i JWE [-n] [-k JWK(Set) ...] [-o PLD]"

void *
jcmd_load_data(const char *file, size_t *len);

json_t *
jcmd_load_json(const char *file, const char *raw,
               json_t *(*conv)(const char *));

bool
jcmd_dump_data(const char *filename, const uint8_t buf[], size_t len);

bool
jcmd_dump_json(const json_t *json, const char *filename,
               char *(*conv)(const json_t *));

bool
jcmd_jwks_extend(json_t *jwks, json_t *jwk_or_jwkset);

int
jcmd_gen(int argc, char *argv[]);

int
jcmd_pub(int argc, char *argv[]);

int
jcmd_thp(int argc, char *argv[]);

int
jcmd_sig(int argc, char *argv[]);

int
jcmd_ver(int argc, char *argv[]);

int
jcmd_enc(int argc, char *argv[]);

int
jcmd_dec(int argc, char *argv[]);
