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

/**
 * \brief José Configuration
 * \defgroup jose_cfg Config
 * @{
 */

#pragma once

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

enum {
    _JOSE_CFG_ERR_BASE = 0x1053000000000000ULL,
    JOSE_CFG_ERR_JWK_INVALID,
    JOSE_CFG_ERR_JWK_MISMATCH,
    JOSE_CFG_ERR_JWK_DENIED,
    JOSE_CFG_ERR_ALG_NOTSUP,
    JOSE_CFG_ERR_ALG_NOINFER,
    JOSE_CFG_ERR_JWS_INVALID,
};

#ifdef DOXYGEN
/**
 * Defines a jose_cfg_t which calls jose_cfg_decref() at end of scope.
 *
 * For example:
 *
 *     void foo() {
 *         jose_cfg_auto_t *cfg = jose_cfg();
 *         // jose_cfg_decref() implicitly called
 *     }
 */
typedef jose_cfg_t jose_cfg_auto_t;
#else
#define jose_cfg_auto_t jose_cfg_t __attribute__((cleanup(jose_cfg_auto)))
#endif

typedef struct jose_cfg jose_cfg_t;
typedef void (jose_cfg_err_t)(void *misc, const char *file, int line,
                              uint64_t err, const char *fmt, va_list ap);

/**
 * Custom allocator function type signatures
 */
typedef void* (*jose_malloc_t)(size_t size);
typedef void* (*jose_realloc_t)(void *ptr, size_t size);
typedef void* (*jose_calloc_t)(size_t nmemb, size_t size);
typedef void  (*jose_free_t)(void *ptr);

/**
 * Global memory allocator function pointers
 * These can be overridden using jose_set_alloc()
 */
extern jose_malloc_t jose_malloc;
extern jose_realloc_t jose_realloc;
extern jose_calloc_t jose_calloc;
extern jose_free_t jose_free;

/**
 * Creates a new configuration instance.
 *
 * \return A newly-allocated configuration instance.
 */
jose_cfg_t *
jose_cfg(void);

void
jose_cfg_auto(jose_cfg_t **cfg);

/**
 * Increases the reference count of a configuration instance.
 *
 * This function always succeeds.
 *
 * \param cfg  The configuration context.
 * \return     The value of \p cfg (for convenience).
 */
jose_cfg_t *
jose_cfg_incref(jose_cfg_t *cfg);

/**
 * Decreases the reference count of a configuration instance.
 *
 * When the reference count reaches zero, the configuration instance is freed.
 *
 * \param cfg  The configuration context.
 */
void
jose_cfg_decref(jose_cfg_t *cfg);

/**
 * Sets the error handler function for this configuration instance.
 *
 * The value of \p misc will be passed to the error handler function.
 *
 * You may pass NULL to \p err to return to the default error handler.
 *
 * \param cfg  The configuration context.
 * \param err  The error handler function you wish to enable.
 * \param misc The miscellaneous data you wish to pass to the error handler.
 */
void
jose_cfg_set_err_func(jose_cfg_t *cfg, jose_cfg_err_t *err, void *misc);

/**
 * Gets the miscellaneous data associated with the current error handler.
 *
 * \param cfg  The configuration context.
 * \return     The miscellaneous data associated with the error handler.
 */
void *
jose_cfg_get_err_misc(jose_cfg_t *cfg);

#ifdef DOXYGEN
/**
 * Submit an error.
 *
 * The error handler will be called with the error provided.
 *
 * \param cfg  The configuration context (optional).
 * \param err  The number corresponding to this error type.
 * \param fmt  A printf()-style format string.
 * \param ...  The printf()-style arguments.
 */
void
jose_cfg_err(jose_cfg_t *cfg, uint64_t err, const char *fmt, ...);
#else
void __attribute__((format(printf, 5, 6)))
jose_cfg_err(jose_cfg_t *cfg, const char *file, int line, uint64_t err,
             const char *fmt, ...);

#define jose_cfg_err(cfg, err, ...) \
    jose_cfg_err(cfg, __FILE__, __LINE__, err, __VA_ARGS__)
#endif

/**
 * Set custom memory allocator functions for JOSE operations globally.
 *
 * This allows you to override the default malloc/realloc/free used
 * throughout the JOSE library. All JOSE operations will use these
 * custom allocators once set. Useful for:
 * - Memory debugging and tracking
 * - Custom memory pools
 * - Secure memory allocation
 * - Cross-DLL memory management on Windows
 *
 * @param pmalloc Custom malloc function
 * @param prealloc Custom realloc function 
 * @param pcalloc Custom calloc function
 * @param pfree   Custom free function
 * @return        0 on success, errno on error
 */
int
jose_set_alloc(jose_malloc_t pmalloc, jose_realloc_t prealloc, jose_free_t pfree, jose_calloc_t pcalloc);

/**
 * Get current memory allocator functions.
 *
 * @param pmalloc Pointer to store current malloc function
 * @param prealloc Pointer to store current realloc function
 * @param pcalloc Pointer to store current calloc function
 * @param pfree   Pointer to store current free function
 */
void
jose_get_alloc(jose_malloc_t *pmalloc, jose_realloc_t *prealloc, jose_free_t *pfree, jose_calloc_t *pcalloc);

/**
 * Reset global allocators to system defaults.
 * Useful for testing or when you want to stop using custom allocators.
 */
void
jose_reset_alloc(void);

/** @} */
