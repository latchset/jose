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
 * \brief IO Chaining
 * \defgroup jose_io IO
 * @{
 */

#pragma once

#include "cfg.h"
#include <stdbool.h>
#include <stdio.h>

#ifdef DOXYGEN
/**
 * Defines a jose_io_t which calls jose_io_decref() at end of scope.
 *
 * For example:
 *
 *     void foo() {
 *         uint8_t *buf = NULL;
 *         size_t len = 0;
 *         jose_io_auto_t *io = jose_io_malloc(NULL, &buf, &len);
 *         // jose_io_decref() implicitly called
 *     }
 */
typedef jose_io_t jose_io_auto_t;

/**
 * The interface for chained IO.
 *
 * \see jose_io_malloc()
 * \see jose_io_buffer()
 * \see jose_io_file()
 * \see jose_io_multiplex()
 * \see jose_b64_enc_io()
 * \see jose_b64_dec_io()
 * \see jose_jws_sig_io()
 * \see jose_jws_ver_io()
 * \see jose_jwe_dec_io()
 * \see jose_jwe_dec_cek_io()
 * \see jose_jwe_enc_io()
 * \see jose_jwe_enc_cek_io()
 */
typedef struct {
    /**
     * Pushes data into the IO chain.
     *
     * \param io  The jose_io_t entity you are using.
     * \param in  The input buffer.
     * \param len The length of the data in the input buffer.
     * \return    Returns true if all data was consumed, otherwise false.
     */
    bool  (*feed)(jose_io_t *io, const void *in, size_t len);

    /**
     * Completes the IO chain.
     *
     * Any data stored in internal buffers will be flushed.
     *
     * \param io  The jose_io_t entity you are using.
     * \return    Returns true if flushing was successful, otherwise false.
     */
    bool  (*done)(jose_io_t *io);
} jose_io_t;
#else
#define jose_io_auto_t jose_io_t __attribute__((cleanup(jose_io_auto)))

typedef struct jose_io jose_io_t;
struct jose_io {
    size_t  refs;
    bool  (*feed)(jose_io_t *io, const void *in, size_t len);
    bool  (*done)(jose_io_t *io);
    void  (*free)(jose_io_t *io); /* Don't call this. Use jose_io_decref(). */
};
#endif

void
jose_io_auto(jose_io_t **io);

/**
 * Increases the reference count of an IO object.
 *
 * This function always succeeds.
 *
 * \param io The jose_io_t entity you are using.
 * \return   The value of \p io (for convenience).
 */
jose_io_t *
jose_io_incref(jose_io_t *io);

/**
 * Decreases the reference count of an IO object.
 *
 * When the reference count reaches zero, io->free() is called.
 *
 * \param io  The jose_io_t entity you are using.
 */
void
jose_io_decref(jose_io_t *io);

/**
 * Creates a new IO object which collects data into a dynamic buffer.
 *
 * The dynamic buffer is allocated into the \p buf pointer you provided and
 * the length of the buffer is stored in \p len. The pointer referenced by
 * \p buf must remain valid for the entire duration of the returned IO object.
 *
 * The default behavior is for the IO object to zero and free the buffer when
 * it is freed. This means that, by default, you own the buffer pointer but
 * the buffer itself is owned by the IO object. You can, however, steal the
 * buffer by setting the buffer pointer to NULL.
 *
 * \see jose_io_malloc_steal()
 * \param cfg The configuration context (optional).
 * \param buf A buffer pointer pointer.
 * \param len A pointer to the length of the buffer.
 * \return    The new IO object or NULL on error.
 */
jose_io_t *
jose_io_malloc(jose_cfg_t *cfg, void **buf, size_t *len);

/**
 * Steals the buffer created by the jose_io_malloc() IO object.
 *
 * This convenience function simply returns the value of \p *buf and then sets
 * \p *buf to NULL.
 *
 * \see jose_io_malloc()
 * \param buf A pointer to the buffer pointer.
 * \return    The value of \p *buf before it is set to NULL.
 */
void *
jose_io_malloc_steal(void **buf);

/**
 * Creates a new IO object which collects data into a static buffer.
 *
 * The size of \p buf MUST be specified in the variable pointed to by \p len.
 * This will be the maximum data written. However, after the function returns,
 * the variable pointed to by \p len will contain the current length of data in
 * the buffer.
 *
 * Unlike jose_io_malloc(), you own the buffer and it is not zeroed or freed
 * when the IO object is freed.
 *
 * \param cfg The configuration context (optional).
 * \param buf A buffer pointer.
 * \param len A pointer to the length of the buffer.
 * \return    The new IO object or NULL on error.
 */
jose_io_t *
jose_io_buffer(jose_cfg_t *cfg, void *buf, size_t *len);

/**
 * Creates a new IO object which writes data into a FILE.
 *
 * This function DOES NOT take ownership of the FILE. You are still responsible
 * for calling fclose() at the appropriate time.
 *
 * \param cfg  The configuration context (optional).
 * \param file The output file which MUST be opened for writing or appending.
 * \return     The new IO object or NULL on error.
 */
jose_io_t *
jose_io_file(jose_cfg_t *cfg, FILE *file);

/**
 * Creates a new IO object which multiplexes data into multiple IO objects.
 *
 * If \p all is true, the success of all \p nexts is required. Otherwise,
 * all but one of the \p nexts can fail before the error is propagated upward.
 *
 * \param cfg   The configuration context (optional).
 * \param nexts A NULL-terminated array of IO object pointers.
 * \param all   Whether or not the success of all \p nexts is required.
 * \return      The new IO object or NULL on error.
 */
jose_io_t *
jose_io_multiplex(jose_cfg_t *cfg, jose_io_t **nexts, bool all);

/** @} */
