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

#include "../lib/hooks.h" /* for MAX_COMPRESSED_SIZE */

static bool
dec_cmp(json_t *jwe, json_t *jwk, const char* expected_data, size_t expected_len)
{
    bool ret = false;
    char *pt = NULL;
    size_t ptl = 0;

    pt = jose_jwe_dec(NULL, jwe, NULL, jwk, &ptl);
    if (!pt)
        goto error;

    if (ptl != expected_len)
        goto error;

    if (strcmp(pt, expected_data) != 0)
        goto error;

    ret = true;

error:
    free(pt);
    return ret;
}

static bool
dec(json_t *jwe, json_t *jwk)
{
    return dec_cmp(jwe, jwk, "foo", 4);
}

struct zip_test_data_t {
    char* data;
    size_t datalen;
    bool expected;
};

static char*
make_data(size_t len)
{
    assert(len > 0);

    char *data = malloc(len);
    assert(data);

    for (size_t i = 0; i < len; i++) {
        data[i] = 'A' + (random() % 26);
    }
    data[len-1] = '\0';
    return data;
}

int
main(int argc, char *argv[])
{
    json_auto_t *jwke = json_pack("{s:s}", "alg", "ECDH-ES+A128KW");
    json_auto_t *jwkr = json_pack("{s:s}", "alg", "RSA1_5");
    json_auto_t *jwko = json_pack("{s:s}", "alg", "A128KW");
    json_auto_t *jwkz = json_pack("{s:s, s:i}", "kty", "oct", "bytes", 16);
    json_auto_t *set0 = json_pack("{s:[O,O]}", "keys", jwke, jwko);
    json_auto_t *set1 = json_pack("{s:[O,O]}", "keys", jwkr, jwko);
    json_auto_t *set2 = json_pack("{s:[O,O]}", "keys", jwke, jwkr);
    json_auto_t *jwe = NULL;

    assert(jose_jwk_gen(NULL, jwke));
    assert(jose_jwk_gen(NULL, jwkr));
    assert(jose_jwk_gen(NULL, jwko));
    assert(jose_jwk_gen(NULL, jwkz));

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


    json_decref(jwe);
    assert((jwe = json_pack("{s:{s:s,s:s,s:s,s:s}}", "protected", "alg", "A128KW", "enc", "A128GCM", "typ", "JWE", "zip", "DEF")));
    assert(jose_jwe_enc(NULL, jwe, NULL, jwkz, "foo", 4));
    assert(dec(jwe, jwkz));
    assert(!dec(jwe, jwkr));
    assert(!dec(jwe, jwko));
    assert(!dec(jwe, set0));
    assert(!dec(jwe, set1));
    assert(!dec(jwe, set2));

    /* Some tests with "zip": "DEF" */
    struct zip_test_data_t zip[] = {
        {
            .data =  make_data(5),
            .datalen = 5,
            .expected = true,
        },
        {
            .data =  make_data(50),
            .datalen = 50,
            .expected = true,
        },
        {
            .data =  make_data(1000),
            .datalen = 1000,
            .expected = true,
        },
        {
            .data =  make_data(10000000),
            .datalen = 10000000,
            .expected = false, /* compressed len will be ~8000000+
                                * (i.e. > MAX_COMPRESSED_SIZE)
                                */
        },
        {
            .data =  make_data(50000),
            .datalen = 50000,
            .expected = true
        },
        {

            .data = NULL
        }
    };

    for (size_t i = 0; zip[i].data != NULL; i++) {
        json_decref(jwe);
        assert((jwe = json_pack("{s:{s:s,s:s,s:s,s:s}}", "protected", "alg", "A128KW", "enc", "A128GCM", "typ", "JWE", "zip", "DEF")));
        assert(jose_jwe_enc(NULL, jwe, NULL, jwkz, zip[i].data, zip[i].datalen));

        /* Now let's get the ciphertext compressed len. */
        char *ct = NULL;
        size_t ctl = 0;
        assert(json_unpack(jwe, "{s:s%}", "ciphertext", &ct, &ctl) != -1);
        /* And check our expectation is correct. */
        assert(zip[i].expected == (ctl < MAX_COMPRESSED_SIZE));

        assert(dec_cmp(jwe, jwkz, zip[i].data, zip[i].datalen) == zip[i].expected);
        free(zip[i].data);
        zip[i].data = NULL;
    }
    return EXIT_SUCCESS;
}
