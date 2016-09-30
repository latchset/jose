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

#include <jose/hooks.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static jose_jwk_type_t *types;
static jose_jwk_op_t *ops;
static jose_jwk_resolver_t *resolvers;
static jose_jwk_generator_t *generators;
static jose_jwk_hasher_t *hashers;
static jose_jwk_exchanger_t *exchangers;
static jose_jws_signer_t *signers;
static jose_jwe_crypter_t *crypters;
static jose_jwe_wrapper_t *wrappers;
static jose_jwe_zipper_t *zippers;
static jose_plugin_t *plugins;

static const char* builtin_plugins[] = {
    "openssl",
    "zlib",
    NULL
};

void
jose_jwk_register_type(jose_jwk_type_t *type)
{
    type->next = types;
    types = type;
}

jose_jwk_type_t *
jose_jwk_types(void)
{
    return types;
}

void
jose_jwk_register_op(jose_jwk_op_t *op)
{
    op->next = ops;
    ops = op;
}

jose_jwk_op_t *
jose_jwk_ops(void)
{
    return ops;
}

void
jose_jwk_register_resolver(jose_jwk_resolver_t *resolver)
{
    resolver->next = resolvers;
    resolvers = resolver;
}

jose_jwk_resolver_t *
jose_jwk_resolvers(void)
{
    return resolvers;
}

void
jose_jwk_register_generator(jose_jwk_generator_t *generator)
{
    generator->next = generators;
    generators = generator;
}

jose_jwk_generator_t *
jose_jwk_generators(void)
{
    return generators;
}

void
jose_jwk_register_hasher(jose_jwk_hasher_t *hasher)
{
    hasher->next = hashers;
    hashers = hasher;
}

jose_jwk_hasher_t *
jose_jwk_hashers(void)
{
    return hashers;
}

void
jose_jwk_register_exchanger(jose_jwk_exchanger_t *exchanger)
{
    exchanger->next = exchangers;
    exchangers = exchanger;
}

jose_jwk_exchanger_t *
jose_jwk_exchangers(void)
{
    return exchangers;
}

void
jose_jws_register_signer(jose_jws_signer_t *signer)
{
    signer->next = signers;
    signers = signer;
}

jose_jws_signer_t *
jose_jws_signers(void)
{
    return signers;
}

void
jose_jwe_register_crypter(jose_jwe_crypter_t *crypter)
{
    crypter->next = crypters;
    crypters = crypter;
}

jose_jwe_crypter_t *
jose_jwe_crypters(void)
{
    return crypters;
}

void
jose_jwe_register_wrapper(jose_jwe_wrapper_t *wrapper)
{
    wrapper->next = wrappers;
    wrappers = wrapper;
}

jose_jwe_wrapper_t *
jose_jwe_wrappers(void)
{
    return wrappers;
}

void
jose_jwe_register_zipper(jose_jwe_zipper_t *zipper)
{
    zipper->next = zippers;
    zippers = zipper;
}

jose_jwe_zipper_t *
jose_jwe_zippers(void)
{
    return zippers;
}

jose_plugin_t*
jose_plugins()
{
    return plugins;
}

static jose_plugin_t*
jose_get_plugin(const char *name)
{
    jose_plugin_t *plugin;

    if (!name)
        return NULL;

    for (plugin = plugins; plugin; plugin = plugin->next) {
        if (strcmp(plugin->name, name) == 0)
            return plugin;
    }
    return NULL;
}

enum jose_plugin_state
jose_load_plugin(const char *name)
{
    jose_plugin_t *plugin;
    char soname[8 + 64 + 3 + 1] = {0}; /* libjose-NAME.so\x00 */

    if (!name || strlen(name) > 64)
        return JOSE_PLUGIN_FAILED;

    plugin = jose_get_plugin(name);
    if (plugin)
        return plugin->state;

    plugin = calloc(1, sizeof(jose_plugin_t));
    if (plugin == NULL)
        return JOSE_PLUGIN_FAILED;

    snprintf(soname, sizeof(soname), "libjose-%s.so", name);
    plugin->handle = dlopen(soname, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);

    if (plugin->handle)
         plugin->state = JOSE_PLUGIN_LOADED;
    else
         plugin->state = JOSE_PLUGIN_FAILED;

    plugin->name = strdup(name);

    plugin->next = plugins;
    plugins = plugin;

    return plugin->state;
}

bool
jose_load_all_plugins(void)
{
    const char **p;
    size_t errors = 0;

    for (p = builtin_plugins; p && *p; p++) {
        if (jose_load_plugin(*p) != JOSE_PLUGIN_LOADED)
            errors++;
    }
    return errors ? false : true;
}
