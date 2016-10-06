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
#include <jose/hooks.h>

static const struct option opts[] = {
    { "help",      no_argument,       .val = 'h' },
    {}
};

int
jcmd_sup(int argc, char *argv[])
{
    jose_jwk_type_t *type;
    jose_jwk_op_t *op;
    jose_jwk_generator_t *generator;
    jose_jwk_hasher_t *hasher;
    jose_jws_signer_t *signer;
    jose_jwe_crypter_t *crypter;
    jose_jwe_wrapper_t *wrapper;
    jose_jwe_zipper_t *zipper;

    for (int c; (c = getopt_long(argc, argv, "h", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

#define FMT(t) ((t)->next ?  " %s," : " %s")
#define FMTOP(t) ((t)->next ? " [%s]%s/%s," : " [%s]%s/%s")

    fprintf(stdout, "jwk_type:");
    for (type = jose_jwk_types(); type; type = type->next)
        fprintf(stdout, FMT(type), type->kty);

    fprintf(stdout, "\n");

    fprintf(stdout, "jwk_op:");
    for (op = jose_jwk_ops(); op; op = op->next)
        fprintf(stdout, FMTOP(op), op->use, op->pub, op->prv);

    fprintf(stdout, "\n");

    fprintf(stdout, "jwk_generator:");
    for (generator = jose_jwk_generators(); generator; generator = generator->next)
        fprintf(stdout, FMT(generator), generator->kty);

    fprintf(stdout, "\n");

    fprintf(stdout, "jwk_hasher:");
    for (hasher = jose_jwk_hashers(); hasher; hasher = hasher->next)
        fprintf(stdout, FMT(hasher), hasher->name);

    fprintf(stdout, "\n");

    fprintf(stdout, "jws_signer:");
    for (signer = jose_jws_signers(); signer; signer = signer->next)
        fprintf(stdout, FMT(signer), signer->alg);
    fprintf(stdout, "\n");

    fprintf(stdout, "jwe_crypter:");
    for (crypter = jose_jwe_crypters(); crypter; crypter = crypter->next)
        fprintf(stdout, FMT(crypter), crypter->enc);
    fprintf(stdout, "\n");

    fprintf(stdout, "jwe_wrapper:");
    for (wrapper = jose_jwe_wrappers(); wrapper; wrapper = wrapper->next)
        fprintf(stdout, FMT(wrapper), wrapper->alg);
    fprintf(stdout, "\n");

    fprintf(stdout, "jwe_zipper:");
    for (zipper = jose_jwe_zippers(); zipper; zipper = zipper->next)
        fprintf(stdout, FMT(zipper), zipper->zip);
    fprintf(stdout, "\n");

    return EXIT_SUCCESS;
usage:
    fprintf(stderr,
"jose " SUP_USE
"\n"
"\nList all supported and loaded algorithms."
"\n");
    return EXIT_FAILURE;
}
