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
    { "help",     no_argument,       .val = 'h' },

    { "op",       required_argument, .val = 'o' },
    { "any",      no_argument,       .val = 'a' },
    { "input",    required_argument, .val = 'i' },
    { "required", no_argument,       .val = 'r' },
    {}
};

int
jcmd_use(int argc, char *argv[])
{
    json_auto_t *jwk = NULL;
    const char *ops[argc];
    bool req = false;
    bool any = false;
    size_t cnt = 0;

    memset(ops, 0, sizeof(ops));

    for (int c; (c = getopt_long(argc, argv, "ho:ai:r", opts, NULL)) >= 0; ) {
        switch (c) {
        case 'h': goto usage;
        case 'o': ops[cnt++] = optarg; break;
        case 'r': req = true; break;
        case 'a': any = true; break;
        case 'i':
            json_decref(jwk);
            jwk = jcmd_load_json(optarg, NULL, NULL);
            break;
        default:
            fprintf(stderr, "Invalid option: %c!\n", c);
            goto usage;
        }
    }

    if (cnt == 0) {
        fprintf(stderr, "Must specify -o!\n");
        goto usage;
    }

    if (!jwk) {
        fprintf(stderr, "Invalid JWK!\n");
        goto usage;
    }

    for (size_t i = 0; i < cnt; i++) {
        bool allowed = jose_jwk_allowed(jwk, req, ops[i]);
        if (!any && !allowed)
            return EXIT_FAILURE;
        if (any && allowed)
            return EXIT_SUCCESS;
    }

    return any ? EXIT_FAILURE : EXIT_SUCCESS;

usage:
    fprintf(stderr,
"jose " USE_USE
"\n"
"\nValidates that a key can be used for the specified operation(s)."
"\n"
"\n    -i FILE,       --jwk=FILE       JWK input (file)"
"\n    -i -,          --jwk=-          JWK input (stdin)"
"\n"
"\n    -o OP,         --op=OP          Validate the key for OP"
"\n    -o sign,       --op=sign        Validate the key for signing"
"\n    -o verify,     --op=verify      Validate the key for verifying"
"\n    -o encrypt,    --op=encrypt     Validate the key for encrypting"
"\n    -o decrypt,    --op=decrypt     Validate the key for decrypting"
"\n    -o wrapKey,    --op=wrapKey     Validate the key for wrapping"
"\n    -o unwrapKey,  --op=unwrapKey   Validate the key for unwrapping"
"\n    -o deriveKey,  --op=deriveKey   Validate the key for deriving keys"
"\n    -o deriveBits, --op=deriveBits  Validate the key for deriving bits"
"\n"
"\n    -a,            --any            Succeeds if any operation is allowed"
"\n    -r,            --required       Operations must be explicitly allowed"
"\n\n");
    return EXIT_FAILURE;
}
