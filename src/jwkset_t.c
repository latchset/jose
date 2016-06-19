/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwkset.h"

#include <assert.h>

int
main(int argc, char *argv[])
{
    json_t *a = NULL;
    json_t *b = NULL;
    json_t *c = NULL;

    a = json_pack("{s:[{s:s},{s:s},{s:s,s:s,s:s,s:s,s:s,s:s,s:s}]}", "keys",
                  "k", "", "d", "", "d", "", "p", "", "q", "", "dp", "",
                  "dq", "", "qi", "", "oth", "");
    assert(json_is_object(a));

    b = jose_jwkset_dup(a, true);
    assert(json_equal(a, b));
    json_decref(a);

    a = jose_jwkset_dup(b, false);
    assert(!json_equal(a, b));
    json_decref(b);
    b = json_pack("{s:[{}, {}, {}]}", "keys");
    assert(json_is_object(b));
    assert(json_equal(a, b));
    json_decref(b);

    b = json_pack("[{}, {}, {}]");
    assert(json_is_array(b));
    c = jose_jwkset_dup(b, true);
    assert(json_is_object(c));
    assert(json_equal(a, c));
    json_decref(c);
    c = jose_jwkset_dup(b, false);
    assert(json_is_object(c));
    assert(json_equal(a, c));
    json_decref(c);
    json_decref(b);
    json_decref(a);

    return 0;
}
