/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jose/jwk.h>
#include <assert.h>

static const struct {
    const char *jwk;
    bool required;
    bool allowed;
} perms[] = {
    { "{}",                                             true,  false },
    { "{}",                                             false, true  },

    { "{\"use\": \"sig\"}",                             true,  false },
    { "{\"use\": \"sig\"}",                             false, false },

    { "{\"use\": \"enc\"}",                             true,  true  },
    { "{\"use\": \"enc\"}",                             false, true  },

    { "{\"key_ops\": []}",                              true,  false },
    { "{\"key_ops\": []}",                              false, false },

    { "{\"key_ops\": [\"sign\"]}",                      true,  false },
    { "{\"key_ops\": [\"sign\"]}",                      false, false },

    { "{\"key_ops\": [\"encrypt\"]}",                   true,  true  },
    { "{\"key_ops\": [\"encrypt\"]}",                   false, true  },

    { "{\"key_ops\": [\"encrypt\", \"decrypt\"]}",      true,  true  },
    { "{\"key_ops\": [\"encrypt\", \"decrypt\"]}",      false, true  },

    { "{\"use\": \"sig\", \"key_ops\": [\"encrypt\"]}", true,  false },
    { "{\"use\": \"sig\", \"key_ops\": [\"encrypt\"]}", false, false },

    { "{\"use\": \"enc\", \"key_ops\": [\"encrypt\"]}", true,  true  },
    { "{\"use\": \"enc\", \"key_ops\": [\"encrypt\"]}", false, true  },

    { "{\"use\": \"enc\", \"key_ops\": [\"decrypt\"]}", true,  false },
    { "{\"use\": \"enc\", \"key_ops\": [\"decrypt\"]}", false, false },

    {}
};

int
main(int argc, char *argv[])
{
    for (size_t i = 0; perms[i].jwk; i++) {
        json_t *jwk = NULL;

        fprintf(stderr, "%s\n", perms[i].jwk);
        assert(jwk = json_loads(perms[i].jwk, 0, NULL));

        assert(jose_jwk_allowed(jwk, perms[i].required,
                                NULL, "encrypt") == perms[i].allowed);

        assert(jose_jwk_allowed(jwk, perms[i].required,
                                "enc", "encrypt") == perms[i].allowed);
    }
}
