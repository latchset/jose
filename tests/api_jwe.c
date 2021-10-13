/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2017 Red Hat, Inc.
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
#include <assert.h>
#include <string.h>

static bool
dec(json_t *jwe, json_t *jwk)
{
    bool ret = false;
    char *pt = NULL;
    size_t ptl = 0;

    pt = jose_jwe_dec(NULL, jwe, NULL, jwk, &ptl);
    if (!pt)
        goto error;

    if (ptl != 4)
        goto error;

    if (strcmp(pt, "foo") != 0)
        goto error;

    ret = true;

error:
    free(pt);
    return ret;
}

int
main(int argc, char *argv[])
{
    json_auto_t *jwke = json_pack("{s:s}", "alg", "ECDH-ES+A128KW");
    json_auto_t *jwkr = json_pack("{s:s}", "alg", "RSA1_5");
    json_auto_t *jwko = json_pack("{s:s}", "alg", "A128KW");
    json_auto_t *set0 = json_pack("{s:[O,O]}", "keys", jwke, jwko);
    json_auto_t *set1 = json_pack("{s:[O,O]}", "keys", jwkr, jwko);
    json_auto_t *set2 = json_pack("{s:[O,O]}", "keys", jwke, jwkr);
    json_auto_t *jwe = NULL;

    assert(jose_jwk_gen(NULL, jwke));
    assert(jose_jwk_gen(NULL, jwkr));
    assert(jose_jwk_gen(NULL, jwko));

    json_decref(jwe);
    assert((jwe = json_object()));
    assert(jose_jwe_enc(NULL, jwe, NULL, jwke, "foo", 4));
    assert(dec(jwe, jwke));
    assert(!dec(jwe, jwkr));
    assert(!dec(jwe, jwko));
    assert(dec(jwe, set0));
    assert(!dec(jwe, set1));
    assert(dec(jwe, set2));

    json_decref(jwe);
    assert((jwe = json_object()));
    assert(jose_jwe_enc(NULL, jwe, NULL, jwkr, "foo", 4));
    assert(!dec(jwe, jwke));
    assert(dec(jwe, jwkr));
    assert(!dec(jwe, jwko));
    assert(!dec(jwe, set0));
    assert(dec(jwe, set1));
    assert(dec(jwe, set2));

    json_decref(jwe);
    assert((jwe = json_object()));
    assert(jose_jwe_enc(NULL, jwe, NULL, jwko, "foo", 4));
    assert(!dec(jwe, jwke));
    assert(!dec(jwe, jwkr));
    assert(dec(jwe, jwko));
    assert(dec(jwe, set0));
    assert(dec(jwe, set1));
    assert(!dec(jwe, set2));

    json_decref(jwe);
    assert((jwe = json_object()));
    assert(jose_jwe_enc(NULL, jwe, NULL, set0, "foo", 4));
    assert(dec(jwe, jwke));
    assert(!dec(jwe, jwkr));
    assert(dec(jwe, jwko));
    assert(dec(jwe, set0));
    assert(dec(jwe, set1));
    assert(dec(jwe, set2));

    return EXIT_SUCCESS;
}
