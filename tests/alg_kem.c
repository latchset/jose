/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2026 Red Hat, Inc.
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
#include <jose/jwk.h>
#include <jose/b64.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

static void
test_roundtrip(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *pub = NULL;
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;
    const char *ss1 = NULL;
    const char *ss2 = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    pub = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub));
    assert(!json_object_get(pub, "priv"));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);
    assert(json_object_get(enc, "ct"));
    assert(json_object_get(enc, "ss"));

    ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    assert(ss1);

    dec = jose_jwk_kem_dec(NULL, jwk, json_object_get(enc, "ct"));
    assert(dec);

    ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss2);

    assert(strcmp(ss1, ss2) == 0);
}

static void
test_implicit_rejection(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;
    json_auto_t *corrupt_ct = NULL;
    const char *ss1 = NULL;
    const char *ss2 = NULL;
    uint8_t *ct_raw = NULL;
    size_t ct_len = 0;

    assert(jose_jwk_gen(NULL, jwk));

    json_auto_t *pub = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);

    ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    assert(ss1);

    json_t *ct = json_object_get(enc, "ct");
    ct_len = jose_b64_dec(ct, NULL, 0);
    ct_raw = malloc(ct_len);
    assert(ct_raw);
    assert(jose_b64_dec(ct, ct_raw, ct_len) == ct_len);

    ct_raw[ct_len / 2] ^= 0x01;
    corrupt_ct = jose_b64_enc(ct_raw, ct_len);
    free(ct_raw);
    assert(corrupt_ct);

    dec = jose_jwk_kem_dec(NULL, jwk, corrupt_ct);
    assert(dec);

    ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss2);
    assert(strcmp(ss1, ss2) != 0);
}

static void
test_cross_key(const jose_hook_alg_t *a)
{
    json_auto_t *jwk1 = json_pack("{s:s}", "alg", a->name);
    json_auto_t *jwk2 = json_pack("{s:s}", "alg", a->name);
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;
    const char *ss1 = NULL;
    const char *ss2 = NULL;

    assert(jose_jwk_gen(NULL, jwk1));
    assert(jose_jwk_gen(NULL, jwk2));

    json_auto_t *pub1 = json_deep_copy(jwk1);
    assert(jose_jwk_pub(NULL, pub1));

    enc = jose_jwk_kem_enc(NULL, pub1);
    assert(enc);

    ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    assert(ss1);

    dec = jose_jwk_kem_dec(NULL, jwk2, json_object_get(enc, "ct"));
    assert(dec);

    ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss2);
    assert(strcmp(ss1, ss2) != 0);
}

static void
test_pub_only_decap_fails(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *pub = NULL;
    json_auto_t *enc = NULL;
    json_auto_t *dec = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    pub = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub));

    enc = jose_jwk_kem_enc(NULL, pub);
    assert(enc);

    dec = jose_jwk_kem_dec(NULL, pub, json_object_get(enc, "ct"));
    assert(!dec);
}

static void
test_key_ops(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_t *ops = NULL;
    const char *op = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    ops = json_object_get(jwk, "key_ops");
    assert(json_is_array(ops));
    assert(json_array_size(ops) == 1);

    op = json_string_value(json_array_get(ops, 0));
    assert(op);
    assert(strcmp(op, "deriveKey") == 0);
}

static void
test_thumbprint(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    json_auto_t *thp = NULL;

    assert(jose_jwk_gen(NULL, jwk));

    thp = jose_jwk_thp(NULL, jwk, "S256");
    assert(thp);
    assert(json_is_string(thp));
    assert(json_string_length(thp) > 0);
}

static void
test_seed_format(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    assert(jose_jwk_gen(NULL, jwk));

    size_t priv_len = jose_b64_dec(json_object_get(jwk, "priv"), NULL, 0);
    assert(priv_len == 64);
}

static void
test_seed_determinism(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    assert(jose_jwk_gen(NULL, jwk));

    const char *pub1 = json_string_value(json_object_get(jwk, "pub"));
    const char *priv_b64 = json_string_value(json_object_get(jwk, "priv"));
    assert(pub1 && priv_b64);

    json_auto_t *jwk2 = json_pack("{s:s,s:s,s:s}",
                                  "kty", "AKP",
                                  "alg", a->name,
                                  "priv", priv_b64);
    assert(jwk2);

    json_auto_t *pub_jwk = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub_jwk));

    json_auto_t *enc = jose_jwk_kem_enc(NULL, pub_jwk);
    assert(enc);

    json_auto_t *dec = jose_jwk_kem_dec(NULL, jwk2, json_object_get(enc, "ct"));
    assert(dec);

    const char *ss1 = json_string_value(json_object_get(json_object_get(enc, "ss"), "k"));
    const char *ss2 = json_string_value(json_object_get(dec, "k"));
    assert(ss1 && ss2);
    assert(strcmp(ss1, ss2) == 0);
}

static void
test_wrong_priv_len(const jose_hook_alg_t *a)
{
    json_auto_t *jwk = json_pack("{s:s}", "alg", a->name);
    assert(jose_jwk_gen(NULL, jwk));

    json_auto_t *pub_jwk = json_deep_copy(jwk);
    assert(jose_jwk_pub(NULL, pub_jwk));

    json_auto_t *enc = jose_jwk_kem_enc(NULL, pub_jwk);
    assert(enc);

    unsigned char bad_priv[32];
    memset(bad_priv, 0x42, sizeof(bad_priv));
    json_auto_t *bad_jwk = json_pack("{s:s,s:s,s:O,s:o}",
                                     "kty", "AKP",
                                     "alg", a->name,
                                     "pub", json_object_get(jwk, "pub"),
                                     "priv", jose_b64_enc(bad_priv, sizeof(bad_priv)));
    assert(bad_jwk);

    json_auto_t *dec = jose_jwk_kem_dec(NULL, bad_jwk, json_object_get(enc, "ct"));
    assert(!dec);
}

static void
test_invalid_pub_key(void)
{
    /* Use a wrong-length buffer: ML-KEM-768 expects 1184 bytes */
    unsigned char bad_pub[100];
    memset(bad_pub, 0x42, sizeof(bad_pub));

    json_auto_t *pub_b64 = jose_b64_enc(bad_pub, sizeof(bad_pub));
    assert(pub_b64);

    json_auto_t *jwk = json_pack("{s:s,s:s,s:O}",
                                 "kty", "AKP",
                                 "alg", "ML-KEM-768",
                                 "pub", pub_b64);
    assert(jwk);

    json_auto_t *result = jose_jwk_kem_enc(NULL, jwk);
    assert(!result);
}

int
main(int argc, char *argv[])
{
    bool found = false;

    for (const jose_hook_alg_t *a = jose_hook_alg_list(); a; a = a->next) {
        if (a->kind != JOSE_HOOK_ALG_KIND_KEM)
            continue;

        found = true;
        fprintf(stderr, "alg: %s\n", a->name);

        test_roundtrip(a);
        fprintf(stderr, "  roundtrip: OK\n");

        test_implicit_rejection(a);
        fprintf(stderr, "  implicit rejection: OK\n");

        test_cross_key(a);
        fprintf(stderr, "  cross-key rejection: OK\n");

        test_pub_only_decap_fails(a);
        fprintf(stderr, "  pub-only decap rejected: OK\n");

        test_key_ops(a);
        fprintf(stderr, "  key_ops: OK\n");

        test_thumbprint(a);
        fprintf(stderr, "  thumbprint: OK\n");

        test_seed_format(a);
        fprintf(stderr, "  seed format (64 bytes): OK\n");

        test_seed_determinism(a);
        fprintf(stderr, "  seed determinism: OK\n");

        test_wrong_priv_len(a);
        fprintf(stderr, "  wrong priv length rejected: OK\n");
    }

    if (!found) {
        fprintf(stderr, "No KEM algorithms available (OpenSSL < 3.5?)\n");
        return 77;
    }

    test_invalid_pub_key();
    fprintf(stderr, "  invalid pub key rejected: OK\n");

    return EXIT_SUCCESS;
}
