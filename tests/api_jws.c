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

int
main(int argc, char *argv[])
{
    json_auto_t *jwke = json_pack("{s:s}", "alg", "ES256");
    json_auto_t *jwkr = json_pack("{s:s}", "alg", "RS256");
    json_auto_t *jwkh = json_pack("{s:s}", "alg", "HS256");
    json_auto_t *set0 = json_pack("{s:[O,O]}", "keys", jwke, jwkh);
    json_auto_t *set1 = json_pack("{s:[O,O]}", "keys", jwkr, jwkh);
    json_auto_t *set2 = json_pack("{s:[O,O]}", "keys", jwke, jwkr);
    json_auto_t *jws = NULL;

    assert(jose_jwk_gen(NULL, jwke));
    assert(jose_jwk_gen(NULL, jwkr));
    assert(jose_jwk_gen(NULL, jwkh));

    json_decref(jws);
    assert((jws = json_pack("{s:s}", "payload", "foo")));
    assert(jose_jws_sig(NULL, jws, NULL, jwke));
    assert(jose_jws_ver(NULL, jws, NULL, jwke, false));
    assert(jose_jws_ver(NULL, jws, NULL, set0, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set0, true));
    assert(!jose_jws_ver(NULL, jws, NULL, set1, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set1, true));
    assert(jose_jws_ver(NULL, jws, NULL, set2, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set2, true));

    json_decref(jws);
    assert((jws = json_pack("{s:s}", "payload", "foo")));
    assert(jose_jws_sig(NULL, jws, NULL, jwkr));
    assert(jose_jws_ver(NULL, jws, NULL, jwkr, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set0, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set0, true));
    assert(jose_jws_ver(NULL, jws, NULL, set1, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set1, true));
    assert(jose_jws_ver(NULL, jws, NULL, set2, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set2, true));

    json_decref(jws);
    assert((jws = json_pack("{s:s}", "payload", "foo")));
    assert(jose_jws_sig(NULL, jws, NULL, jwkh));
    assert(jose_jws_ver(NULL, jws, NULL, jwkh, false));
    assert(jose_jws_ver(NULL, jws, NULL, set0, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set0, true));
    assert(jose_jws_ver(NULL, jws, NULL, set1, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set1, true));
    assert(!jose_jws_ver(NULL, jws, NULL, set2, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set2, true));

    json_decref(jws);
    assert((jws = json_pack("{s:s}", "payload", "foo")));
    assert(jose_jws_sig(NULL, jws, NULL, set0));
    assert(jose_jws_ver(NULL, jws, NULL, set0, false));
    assert(jose_jws_ver(NULL, jws, NULL, set0, true));
    assert(jose_jws_ver(NULL, jws, NULL, set1, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set1, true));
    assert(jose_jws_ver(NULL, jws, NULL, set2, false));
    assert(!jose_jws_ver(NULL, jws, NULL, set2, true));

    return EXIT_SUCCESS;
}
