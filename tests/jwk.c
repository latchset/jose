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
