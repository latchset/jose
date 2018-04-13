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

#include "../jose.h"

#define jcmd_b64_opt_auto_t __JCMD_AUTO(jcmd_b64_opt)

typedef struct {
    FILE *input;
    FILE *output;
    bool conv;
} jcmd_b64_opt_t;

static inline void
jcmd_b64_opt_cleanup(jcmd_b64_opt_t *opt)
{
    jcmd_file_cleanup(&opt->input);
    jcmd_file_cleanup(&opt->output);
}
