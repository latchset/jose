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

#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define jose_buf_auto_t jose_buf_t __attribute__((cleanup(jose_buf_auto)))
#endif

#define JOSE_BUF_FLAG_NONE 0
#define JOSE_BUF_FLAG_WIPE (1 << 0)

typedef struct {
    size_t size;
    uint8_t data[];
} jose_buf_t;

jose_buf_t *
jose_buf(size_t size, uint64_t flags);

jose_buf_t *
jose_buf_incref(jose_buf_t *buf);

void
jose_buf_decref(jose_buf_t *buf);

void
jose_buf_auto(jose_buf_t **buf);
