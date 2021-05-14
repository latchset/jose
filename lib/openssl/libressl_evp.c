/* ====================================================================
 * Copyright (c) 2001-2018 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */
/* This code is from openssl 1.0.2r */
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "libressl_evp.h"

static const unsigned char default_iv[] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
};

static size_t CRYPTO_128_wrap(void *key, const unsigned char *iv,
                       unsigned char *out,
                       const unsigned char *in, size_t inlen,
                       block128_f block)
{
    unsigned char *A, B[16], *R;
    size_t i, j, t;
    if ((inlen & 0x7) || (inlen < 8) || (inlen > CRYPTO128_WRAP_MAX))
        return 0;
    A = B;
    t = 1;
    memmove(out + 8, in, inlen);
    if (!iv)
        iv = default_iv;

    memcpy(A, iv, 8);

    for (j = 0; j < 6; j++) {
        R = out + 8;
        for (i = 0; i < inlen; i += 8, t++, R += 8) {
            memcpy(B + 8, R, 8);
            block(B, B, key);
            A[7] ^= (unsigned char)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (unsigned char)((t >> 8) & 0xff);
                A[5] ^= (unsigned char)((t >> 16) & 0xff);
                A[4] ^= (unsigned char)((t >> 24) & 0xff);
            }
            memcpy(R, B + 8, 8);
        }
    }
    memcpy(out, A, 8);
    return inlen + 8;
}

static size_t CRYPTO_128_unwrap(void *key, const unsigned char *iv,
                         unsigned char *out,
                         const unsigned char *in, size_t inlen,
                         block128_f block)
{
    unsigned char *A, B[16], *R;
    size_t i, j, t;
    inlen -= 8;
    if ((inlen & 0x7) || (inlen < 16) || (inlen > CRYPTO128_WRAP_MAX))
        return 0;
    A = B;
    t = 6 * (inlen >> 3);
    memcpy(A, in, 8);
    memmove(out, in + 8, inlen);
    for (j = 0; j < 6; j++) {
        R = out + inlen - 8;
        for (i = 0; i < inlen; i += 8, t--, R -= 8) {
            A[7] ^= (unsigned char)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (unsigned char)((t >> 8) & 0xff);
                A[5] ^= (unsigned char)((t >> 16) & 0xff);
                A[4] ^= (unsigned char)((t >> 24) & 0xff);
            }
            memcpy(B + 8, R, 8);
            block(B, B, key);
            memcpy(R, B + 8, 8);
        }
    }
    if (!iv)
        iv = default_iv;
    if (memcmp(A, iv, 8)) {
        OPENSSL_cleanse(out, inlen);
        return 0;
    }
    return inlen;
}

static int aes_wrap_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    EVP_AES_WRAP_CTX *wctx = ctx->cipher_data;
    if (!iv && !key)
	return 1;
    if (key) {
        if (ctx->encrypt)
            AES_set_encrypt_key(key, ctx->key_len * 8, &wctx->ks.ks);
        else
            AES_set_decrypt_key(key, ctx->key_len * 8, &wctx->ks.ks);
        if (!iv)
            wctx->iv = NULL;
}
    if (iv) {
        memcpy(ctx->iv, iv, 8);
        wctx->iv = ctx->iv;
    }
    return 1;
}

static int aes_wrap_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen)
{
    EVP_AES_WRAP_CTX *wctx = ctx->cipher_data;
    size_t rv;
    if (!in)
        return 0;
    if (inlen % 8)
        return -1;
    if (ctx->encrypt && inlen < 8)
        return -1;
    if (!ctx->encrypt && inlen < 16)
        return -1;
    if (!out) {
        if (ctx->encrypt)
            return inlen + 8;
        else
            return inlen - 8;
    }
    if (ctx->encrypt)
        rv = CRYPTO_128_wrap(&wctx->ks.ks, wctx->iv, out, in, inlen,
                             (block128_f) AES_encrypt);
    else
        rv = CRYPTO_128_unwrap(&wctx->ks.ks, wctx->iv, out, in, inlen,
                               (block128_f) AES_decrypt);
    return rv ? (int)rv : -1;
}

static const EVP_CIPHER aes_128_wrap = {
    NID_id_aes128_wrap,
    8, 16, 8, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL

};

const EVP_CIPHER *EVP_aes_128_wrap(void){
	return &aes_128_wrap;
}

static const EVP_CIPHER aes_192_wrap = {
    NID_id_aes192_wrap,
    8, 24, 8, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_192_wrap(void){
	return &aes_192_wrap;
}

static const EVP_CIPHER aes_256_wrap = {
    NID_id_aes256_wrap,
    8, 32, 8, WRAP_FLAGS,
    aes_wrap_init_key, aes_wrap_cipher,
    NULL,
    sizeof(EVP_AES_WRAP_CTX),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_aes_256_wrap(void) {
	return &aes_256_wrap;
}
