/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "../b64.h"
#include "../jwk.h"
#include <openssl/rand.h>

static bool
generate(json_t *jwk)
{
    json_int_t len = 0;
    uint8_t *buf = NULL;

    if (json_unpack(jwk, "{s:i}", "bytes", &len) == -1)
        return false;

    buf = malloc(len);
    if (!buf)
        return false;

    if (RAND_bytes(buf, len) <= 0) {
        free(buf);
        return false;
    }

    if (json_object_set_new(jwk, "k", jose_b64_encode_json(buf, len)) == -1) {
        free(buf);
        return false;
    }
    free(buf);

    return json_object_del(jwk, "bytes") == 0;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_generator_t generator = {
        .kty = "oct",
        .generate = generate
    };

    jose_jwk_register_generator(&generator);
}
