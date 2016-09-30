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

#define _GNU_SOURCE

#include "misc.h"
#include <jose/jose.h>

#include <ctype.h>
#include <string.h>

#include <dlfcn.h>

static json_t *
compact_to_obj(const char *compact, ...)
{
    json_auto_t *out = NULL;
    size_t count = 0;
    size_t c = 0;
    va_list ap;

    if (!compact)
        return NULL;

    va_start(ap, compact);
    while (va_arg(ap, const char *))
        count++;
    va_end(ap);

    if (count == 0)
        return NULL;

    size_t len[count];

    memset(len, 0, sizeof(len));

    for (size_t i = 0; compact[i]; i++) {
        if (!isalnum(compact[i]) && !strchr("-_.", compact[i]))
            return NULL;
        else if (compact[i] != '.')
            len[c]++;
        else if (++c > count - 1)
            return NULL;
    }

    if (c != count - 1)
        return NULL;

    out = json_object();
    if (!out)
        return NULL;

    c = 0;
    va_start(ap, compact);
    for (size_t i = 0; i < count; i++) {
        json_t *val = json_stringn(&compact[c], len[i]);
        if (json_object_set_new(out, va_arg(ap, const char *), val) < 0) {
            va_end(ap);
            return NULL;
        }

        c += len[i] + 1;
    }
    va_end(ap);

    if (json_object_size(out) == 0)
        return NULL;

    return json_incref(out);
}

static char *
jws_to_compact(const json_t *jws)
{
    const char *signature = NULL;
    const char *protected = NULL;
    const char *payload = NULL;
    const char *header = NULL;
    char *out = NULL;

    if (json_unpack((json_t *) jws, "{s: s, s: s, s: s, s? s}",
                    "payload", &payload,
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1 &&
        json_unpack((json_t *) jws, "{s: s, s: [{s: s, s: s, s: s, s? s}!]}",
                    "payload", &payload,
                    "signatures",
                    "signature", &signature,
                    "protected", &protected,
                    "header", &header) == -1)
        return NULL;

    if (header)
        return NULL;

    if (asprintf(&out, "%s.%s.%s", protected, payload, signature) < 0)
        return NULL;

    return out;
}

static char *
jwe_to_compact(const json_t *jwe)
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

    if (asprintf(&out, "%s.%s.%s.%s.%s",
                 protected, encrypted_key, iv, ciphertext, tag) < 0)
        return NULL;

    return out;
}

json_t *
jose_from_compact(const char *cmpct)
{
    json_t *jose = NULL;

    jose = compact_to_obj(cmpct, "protected", "encrypted_key",
                         "iv", "ciphertext", "tag", NULL);
    if (!jose)
        jose = compact_to_obj(cmpct, "protected", "payload", "signature", NULL);

    return jose;
}

char *
jose_to_compact(const json_t *jose)
{
    char *cmpct = NULL;

    cmpct = jwe_to_compact(jose);
    if (!cmpct)
        cmpct = jws_to_compact(jose);

    return cmpct;
}

static jose_plugin_t plugins[] = {
    { .name = "openssl",
      .lib = "libjose-openssl.so",
      .load_all = true,
      .state = JOSE_PLUGIN_NOT_LOADED },
    { .name = "zlib",
      .lib = "libjose-zlib.so",
      .load_all = true,
      .state = JOSE_PLUGIN_NOT_LOADED },
    {}
};

#define JOSE_DL_FLAGS (RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL)

static void
load_plugin(jose_plugin_t *plugin) {
    void *lib;

    if (plugin->state == JOSE_PLUGIN_LOADED)
        return;

    lib = dlopen(plugin->lib, JOSE_DL_FLAGS);
    if (lib) {
        plugin->state = JOSE_PLUGIN_LOADED;
        plugin->handle = lib;
    } else
        plugin->state = JOSE_PLUGIN_FAILED;
}

bool
jose_load_all_plugins(void)
{
    int errors = 0;
    for (size_t i = 0; plugins[i].name; i++) {
        jose_plugin_t *plugin = &plugins[i];
        if (plugin->load_all) {
            load_plugin(plugin);
            if (plugin->state != JOSE_PLUGIN_LOADED)
                errors++;
        }
    }
    return errors ? false : true;
}

enum jose_plugin_state
jose_load_plugin(const char *name)
{
    for (size_t i = 0; plugins[i].name; i++) {
        if (strcmp(name, plugins[i].name) == 0) {
            load_plugin(&plugins[i]);
            return plugins[i].state;
        }
    }
    return JOSE_PLUGIN_NOT_FOUND;
}

jose_plugin_t*
jose_get_plugins(void) {
    return plugins;
}
