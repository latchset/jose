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

static const jcmd_doc_t jcmd_jwk_doc_input[] = {
    { .arg = "JSON", .doc="Parse JWK(Set) from JSON" },
    { .arg = "FILE", .doc="Read JWK(Set) from FILE" },
    { .arg = "-",    .doc="Read JWK(Set) standard input" },
    {}
};

static const jcmd_doc_t jcmd_jwk_doc_output[] = {
    { .arg = "FILE", .doc="Write JWK(Set) to FILE" },
    { .arg = "-",    .doc="Write JWK(Set) to standard input" },
    {}
};

static const jcmd_doc_t jcmd_jwk_doc_set[] = {
    { .doc="Always output a JWKSet" },
    {}
};
