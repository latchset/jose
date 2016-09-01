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
#include <string.h>

static const struct option opts[] = {
    { "help",   no_argument,       .val = 'h' },

    { "input",  required_argument, .val = 'i' },
    { "number", required_argument, .val = 'n' },
    { "output", required_argument, .val = 'o' },
    {}
};

int
jcmd_hdr(int argc, char *argv[])
{
    const json_t *rcps = NULL;
    const json_t *sigs = NULL;
    const json_t *shrd = NULL;
    json_auto_t *jose = NULL;
    json_auto_t *hdr = NULL;
    const char *sig = NULL;
    const char *out = "-";
    char *in = NULL;
    size_t len = 0;
    size_t n = 0;

    for (int c; (c = getopt_long(argc, argv, "hi:o:", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': out = optarg; break;
        case 'n': n = strtoull(optarg, NULL, 10); break;
        case 'i':
            free(in);
            in = jcmd_load_data(optarg, &len);
            break;
        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            free(in);
            goto usage;
        }
    }

    if (!in) {
        fprintf(stderr, "Error reading input!\n");
        goto usage;
    }

    jose = jose_jwe_from_compact(in);
    if (!jose) {
        jose = jose_jws_from_compact(in);
        if (!jose)
            jose = json_loadb(in, len, 0, NULL);
    }

    free(in);
    if (!jose) {
        fprintf(stderr, "Invalid JWS or JWE!\n");
        return EXIT_FAILURE;
    }

    if (json_unpack(jose, "{s?o,s?o,s?o,s?s}",
                    "recipients", &rcps, "header", &shrd,
                    "signatures", &sigs, "signature", &sig) != 0) {
        fprintf(stderr, "Error unpacking JWS or JWE!\n");
        return EXIT_FAILURE;
    }

    if (json_is_array(rcps)) {
        hdr = jose_jwe_merge_header(jose, json_array_get(rcps, n));
    } else if (json_is_array(sigs)) {
        hdr = jose_jws_merge_header(json_array_get(sigs, n));
    } else if (json_is_object(shrd)) {
        hdr = jose_jwe_merge_header(jose, jose);
    } else if (sig) {
        hdr = jose_jws_merge_header(jose);
    } else {
        hdr = jose_jwe_merge_header(jose, NULL);
    }

    if (!hdr) {
        fprintf(stderr, "Error merging headers!\n");
        return EXIT_FAILURE;
    }

    if (!jcmd_dump_json(hdr, out, NULL))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;

usage:
    fprintf(stderr,
"jose " HDR_USE
"\n"
"\nExtracts the JOSE Header."
"\n"
"\nNOTE WELL: This command does not validate the protected header!"
"\n"
"\n    -i FILE,   --jwk=FILE       JWS or JWE input (file)"
"\n    -i -,      --jwk=-          JWS or JWE input (stdin)"
"\n"
"\n    -n NUM,    --number=NUM     Recipient or signature number (default: 0)"
"\n"
"\n    -o FILE,   --output=FILE    JOSE Header output (file)"
"\n    -o -,      --output=-       JOSE Header output (stdout; default)"
"\n\n");
    return EXIT_FAILURE;
}
