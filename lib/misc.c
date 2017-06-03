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

#include "misc.h"
#include <jose/b64.h>
#include <string.h>

bool
encode_protected(json_t *obj)
{
    json_t *p = NULL;

    if (json_unpack(obj, "{s?o}", "protected", &p) == -1)
        return false;

    if (!p || json_is_string(p))
        return true;

    if (!json_is_object(p))
        return false;

    return json_object_set_new(obj, "protected", jose_b64_enc_dump(p)) == 0;
}

void
zero(void *mem, size_t len)
{
    memset(mem, 0, len);
}

static void __attribute__((constructor))
constructor(void)
{
    json_object_seed(0);
}
