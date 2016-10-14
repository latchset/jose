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

#include <jose/jose.h>
#include <getopt.h>

#define GEN_USE \
    "gen -t TMPL ... [-o JWK(Set)]"

#define PUB_USE \
    "pub -i JWK(Set) [-o JWK(Set)]"

#define USE_USE \
    "use -i JWK [-a] [-r] -o OP ..."

#define THP_USE \
    "thp -i JWK(Set) [-H HASH] [-o THMB]"

#define EXC_USE \
    "exc [-t TMPL] -l JWK -r JWK [-o JWK]"

#define SIG_USE \
    "sig -i PLD [-t TMPL] [-s SIGT ...] -k JWK(Set) ... [-o JWS] [-c] [-d]"

#define VER_USE \
    "ver -i JWS [-d DTCH] -k JWK(Set) ... [-a] [-o PLD]"

#define ENC_USE \
    "enc -i PLD [-t TMPL] [-r RCPT ...] [-p ...] -k JWK(Set) ... [-c] [-o JWE]"

#define DEC_USE \
    "dec -i JWE [-n] [-k JWK(Set) ...] [-o PLD]"

#define SUP_USE \
    "sup"

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
jcmd_use(int argc, char *argv[]);

int
jcmd_exc(int argc, char *argv[]);

int
jcmd_sig(int argc, char *argv[]);

int
jcmd_ver(int argc, char *argv[]);

int
jcmd_enc(int argc, char *argv[]);

int
jcmd_dec(int argc, char *argv[]);

int
jcmd_sup(int argc, char *argv[]);
