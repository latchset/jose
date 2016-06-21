/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#define _GNU_SOURCE
#include "jwe.h"
#include "b64.h"
#include "conv.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

json_t *
jose_jwe_from_compact(const char *jwe)
{
    return compact_to_obj(jwe, "protected", "encrypted_key",
                          "iv", "ciphertext", "tag", NULL);
}

char *
jose_jwe_to_compact(const json_t *jwe)
{
    const char *encrypted_key = NULL;
    const char *unprotected = NULL;
    const char *ciphertext = NULL;
    const char *protected = NULL;
    const char *header = NULL;
    const char *aad = NULL;
    const char *tag = NULL;
    const char *iv = NULL;
    char *out = NULL;

    if (json_unpack((json_t *) jwe, "{s:s,s:s,s:s,s:s,s:s,s?s,s?s,s?s}",
                    "encrypted_key", &encrypted_key,
                    "ciphertext", &ciphertext,
                    "protected", &protected,
                    "tag", &tag,
                    "iv", &iv,
                    "unprotected", &unprotected,
                    "header", &header,
                    "aad", &aad) == -1 &&
        json_unpack((json_t *) jwe, "{s:s,s:s,s:s,s:s,s:[{s:s,s?s}!],s?s,s?s}",
                    "ciphertext", &ciphertext,
                    "protected", &protected,
                    "tag", &tag,
                    "iv", &iv,
                    "recipients",
                    "encrypted_key", &encrypted_key,
                    "header", &header,
                    "unprotected", &unprotected,
                    "aad", &aad) == -1)
        return NULL;

    if (unprotected || header || aad)
        return NULL;

    asprintf(&out, "%s.%s.%s.%s.%s",
             protected, encrypted_key, iv, ciphertext, tag);

    return out;
}

EVP_PKEY *
jose_jwe_generate_cek(json_t *jwe)
{
    const char *enc = NULL;
    EVP_PKEY *key = NULL;
    uint8_t *buf = NULL;
    json_t *p = NULL;
    json_t *s = NULL;
    size_t len = 0;

    if (json_unpack(jwe, "{s?O,s?o}", "protected", &p,
                    "unprotected", &s) == -1)
        return NULL;

    if (json_is_string(p)) {
        json_t *dec = jose_b64_decode_json_load(p, 0);
        json_decref(p);
        p = dec;
    }

    if (p && !json_is_object(p))
        goto egress;

    if (json_unpack(p, "{s:s}", "enc", &enc) == -1 &&
        json_unpack(s, "{s:s}", "enc", &enc) == -1) {
        enc = "A128GCM";

        if (!p)
            p = json_object();

        if (json_object_set_new(p, "enc", json_string(enc)) == -1 ||
            json_object_set(jwe, "protected", p) == -1)
            goto egress;
    }

    switch (str_to_enum(enc, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256",
                        "A192CBC-HS384", "A256CBC-HS512",NULL)) {
    case 0: len = 16; break;
    case 1: len = 24; break;
    case 2: len = 32; break;
    case 3: len = 32; break;
    case 4: len = 48; break;
    case 5: len = 64; break;
    default: goto egress;
    }

    buf = malloc(len);
    if (!buf)
        goto egress;

    if (RAND_bytes(buf, len) <= 0)
        goto egress;

    key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, buf, len);

egress:
    json_decref(p);
    free(buf);
    return key;
}
