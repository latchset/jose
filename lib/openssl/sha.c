/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include <jose/jwk.h>
#include <openssl/sha.h>

static bool
sha1(const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA1(in, inl, out) != NULL;
}

static bool
sha224(const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA224(in, inl, out) != NULL;
}

static bool
sha256(const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA256(in, inl, out) != NULL;
}

static bool
sha384(const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA384(in, inl, out) != NULL;
}

static bool
sha512(const uint8_t *in, size_t inl, uint8_t out[])
{
    return SHA512(in, inl, out) != NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_hasher_t hashes[] = {
        { NULL, "sha1",   SHA_DIGEST_LENGTH,    sha1   },
        { NULL, "sha224", SHA224_DIGEST_LENGTH, sha224 },
        { NULL, "sha256", SHA256_DIGEST_LENGTH, sha256 },
        { NULL, "sha384", SHA384_DIGEST_LENGTH, sha384 },
        { NULL, "sha512", SHA512_DIGEST_LENGTH, sha512 },
        {}
    };

    for (size_t i = 0; hashes[i].name; i++)
        jose_jwk_register_hasher(&hashes[i]);
}
