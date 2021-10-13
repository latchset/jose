/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright 2020 Red Hat, Inc.
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
#include <jose/openssl.h>
#include <assert.h>
#include <string.h>

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

/*
 * In this test we load a (RSA, 512-bit) PEM file asa n EVP_PKEY*, then
 * convert it to JWK with jose_openssl_jwk_from_EVP_PKEY().
 *
 * Afterwards, we convert this JWK to EVP_PKEY* again, with
 * jose_openssl_jwk_to_EVP_PKEY(), and once more convert the
 * resulting EVP_PKEY* back to JWK with jose_openssl_jwk_from_EVP_PKEY().
 *
 * We then compare the two JWKs, and they should be equal.
 */

int
main(int argc, char *argv[])
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    BIO* pfile = BIO_new_file("rsa512.pem", "r");
    assert(pfile);

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(pfile, NULL, 0, NULL);
    assert(pkey);
    BIO_free(pfile);

    json_auto_t* jwk = jose_openssl_jwk_from_EVP_PKEY(NULL, pkey);
    assert(jwk);

    EVP_PKEY* from_jwk = jose_openssl_jwk_to_EVP_PKEY(NULL, jwk);
    assert(from_jwk);

    json_auto_t* converted_jwk = jose_openssl_jwk_from_EVP_PKEY(NULL, from_jwk);
    assert(converted_jwk);

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(from_jwk);

    assert(json_equal(jwk, converted_jwk));
    return EXIT_SUCCESS;
}
