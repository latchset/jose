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

#include "../lib/hooks.h"
#include <assert.h>
#include <string.h>

static const struct {
    const char *alg;
    const char *msg;
    const char *hsh;
} v[] = {
    { "S1",   "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { "S224", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
    { "S256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
                     "f20015ad" },
    { "S384", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a"
                     "43ff5bed8086072ba1e7cc2358baeca134c825a7" },
    { "S512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee6"
                     "4b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e"
                     "2a9ac94fa54ca49f" },

    { "S1",   "",    "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "S224", "",    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
    { "S256", "",    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
                     "7852b855" },
    { "S384", "",    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf"
                     "63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
    { "S512", "",    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921"
                     "d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81"
                     "a538327af927da3e" },

    {}
};

static void
test(const jose_hook_alg_t *alg, const char *msg,
     const uint8_t *a, size_t al, bool iter)
{
    jose_io_auto_t *buf = NULL;
    jose_io_auto_t *hsh = NULL;
    uint8_t q[alg->hash.size];
    size_t ql = sizeof(q);

    assert(sizeof(q) == al);
    memset(q, 0, sizeof(q));

    buf = jose_io_buffer(NULL, q, &ql);
    assert(buf);

    hsh = alg->hash.hsh(alg, NULL, buf);
    assert(hsh);

    if (iter) {
        for (size_t i = 0; i < strlen(msg); i++)
            assert(hsh->feed(hsh, &msg[i], 1));
    } else {
        assert(hsh->feed(hsh, msg, strlen(msg)));
    }

    assert(hsh->done(hsh));
    assert(ql == al);
    assert(memcmp(q, a, al) == 0);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; v[i].alg; i++) {
        const jose_hook_alg_t *alg = NULL;

        alg = jose_hook_alg_find(JOSE_HOOK_ALG_KIND_HASH, v[i].alg);
        assert(alg);

        uint8_t a[alg->hash.size];

        assert(strlen(v[i].hsh) == sizeof(a) * 2);
        for (size_t j = 0; j < sizeof(a); j++)
            sscanf(&v[i].hsh[j * 2], "%02hhx", &a[j]);

        test(alg, v[i].msg, a, sizeof(a), false);
        test(alg, v[i].msg, a, sizeof(a), true);
    }

    return EXIT_SUCCESS;
}
