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

#pragma once

#include "../jose.h"

static const jcmd_field_t jcmd_jwe_fields[] = {
    { .name = "protected" },
    { .name = "encrypted_key", .mult = "recipients" },
    { .name = "iv" },
    { .name = "ciphertext" },
    { .name = "tag" },
    {}
};

static const jcmd_doc_t jcmd_jwe_doc_input[] = {
    { .arg = "JSON", .doc="Parse JWE from JSON" },
    { .arg = "FILE", .doc="Read JWE from FILE" },
    { .arg = "-",    .doc="Read JWE from standard input" },
    {}
};

static const jcmd_doc_t jcmd_jwe_doc_detached[] = {
    { .arg = "FILE", .doc="Read decoded ciphertext from FILE" },
    { .arg = "-",    .doc="Read decoded ciphertext from standard input" },
    {}
};

static const jcmd_doc_t jcmd_jwe_doc_output[] = {
    { .arg = "FILE", .doc="Write JWE to FILE" },
    { .arg = "-",    .doc="Write JWE to stdout (default)" },
    {}
};

static const jcmd_doc_t jcmd_jwe_doc_detach[] = {
    { .arg = "FILE", .doc="Detach ciphertext and decode to FILE" },
    { .arg = "-",    .doc="Detach ciphertext and decode to standard output" },
    {}
};

static const jcmd_doc_t jcmd_jwe_doc_compact[] = {
    { .doc="Output JWE using compact serialization" },
    {}
};
