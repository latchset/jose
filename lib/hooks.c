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
