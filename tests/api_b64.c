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

#include <jose/jose.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#define NBYTES(size) ((((unsigned long long) size) + 1ULL) / 8ULL)

union encoding {
    uint32_t idx;
    uint8_t  enc[4];
};

static inline void
set(uint8_t *val, uint32_t idx)
{
    const uint8_t n = 1 << (idx % 8);
    uint8_t *p = &val[idx / 8];

    #pragma omp atomic update
    *p |= n;
}

static inline bool
get(uint8_t  *val, uint32_t idx)
{
    const uint8_t n = 1 << (idx % 8);
    uint8_t *p = &val[idx / 8];
    uint8_t v;
    #pragma omp atomic read
    v = *p;
    return (v & n) == n;
}

int
main(int argc, char *argv[])
{
    uint8_t *val = NULL;

    /* Ensure that all one byte encodings are invalid. */
    #pragma omp parallel for
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        union encoding enc = { i };
        uint8_t dec[3] = {};
        assert(jose_b64_dec_buf(enc.enc, 1, dec, sizeof(dec)) == SIZE_MAX);
    }

    /* Test all two-byte encodings. */
    val = calloc(NBYTES(UINT32_MAX), sizeof(uint8_t));
    if (!val)
        return EXIT_FAILURE;

    #pragma omp parallel for shared(val)
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        uint8_t dec[3] = { i };
        union encoding enc = {};
        assert(jose_b64_enc_buf(dec, 1, enc.enc, sizeof(enc.enc)) == 2);
        set(val, enc.idx);
    }

    #pragma omp parallel for shared(val)
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        for (uint16_t j = 0; j <= UINT8_MAX; j++) {
            union encoding enc = { .enc = { i, j } };
            uint8_t dec[3] = {};
            size_t len = 0;
            len = get(val, enc.idx) ? 1 : SIZE_MAX;
            if (jose_b64_dec_buf(enc.enc, 2, dec, sizeof(dec)) != len) {
                fprintf(stderr, "{%hx,%hx}\"%c%c\" != %zu\n",
                                i, j, enc.enc[0], enc.enc[1], len);
                assert(false);
            }
        }
    }

    free(val);

    /* Test all three-byte encodings. */

    val = calloc(NBYTES(UINT32_MAX), sizeof(uint8_t));
    if (!val)
        return EXIT_FAILURE;

    #pragma omp parallel for shared(val)
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        for (uint16_t j = 0; j <= UINT8_MAX; j++) {
            uint8_t dec[3] = { i, j };
            union encoding enc = {};
            assert(jose_b64_enc_buf(dec, 2, enc.enc, sizeof(enc.enc)) == 3);
            set(val, enc.idx);
        }
    }

    #pragma omp parallel for shared(val)
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        for (uint16_t j = 0; j <= UINT8_MAX; j++) {
            for (uint16_t k = 0; k <= UINT8_MAX; k++) {
                union encoding enc = { .enc = { i, j, k } };
                uint8_t dec[3] = {};
                size_t len = 0;
                len = get(val, enc.idx) ? 2 : SIZE_MAX;
                if (jose_b64_dec_buf(enc.enc, 3, dec, sizeof(dec)) != len) {
                    fprintf(stderr, "{%hu,%hu,%hu}\"%c%c%c\" != %zu\n",
                            i, j, k, enc.enc[0], enc.enc[1], enc.enc[2], len);
                    assert(false);
                }
            }
        }
    }

    free(val);

    /* Test all four-byte encodings. */
#if defined(_OPENMP) && _OPENMP >= 201107
    val = calloc(NBYTES(UINT32_MAX), sizeof(uint8_t));
    if (!val)
        return EXIT_FAILURE;

    #pragma omp parallel for shared(val)
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        for (uint16_t j = 0; j <= UINT8_MAX; j++) {
            for (uint16_t k = 0; k <= UINT8_MAX; k++) {
                uint8_t dec[3] = { i, j, k };
                union encoding enc = {};
                assert(jose_b64_enc_buf(dec, 3, enc.enc, sizeof(enc.enc)) == 4);
                set(val, enc.idx);
            }
        }
    }

    #pragma omp parallel for shared(val)
    for (uint16_t i = 0; i <= UINT8_MAX; i++) {
        for (uint16_t j = 0; j <= UINT8_MAX; j++) {
            for (uint16_t k = 0; k <= UINT8_MAX; k++) {
                for (uint16_t l = 0; l <= UINT8_MAX; l++) {
                    union encoding enc = { .enc = { i, j, k, l } };
                    uint8_t dec[3] = {};
                    size_t len = 0;
                    len = get(val, enc.idx) ? 3 : SIZE_MAX;
                    if (jose_b64_dec_buf(enc.enc, 4, dec, sizeof(dec)) != len) {
                        fprintf(stderr, "{%hu,%hu,%hu,%hu}\"%c%c%c%c\" != %zu\n",
                                i, j, k, l, enc.enc[0], enc.enc[1], enc.enc[2], enc.enc[3], len);
                        assert(false);
                    }
                }
            }
        }
    }

    free(val);
#endif
    return 0;
}
