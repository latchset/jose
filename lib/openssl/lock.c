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

#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <pthread.h>

static pthread_mutex_t *locks;

static void
locking_cb(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(locks[type]));
    else
        pthread_mutex_unlock(&(locks[type]));
}

static void
thread_id_cb(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

static void __attribute__((constructor))
locking_setup(void)
{
    int i;

    /* Check if somebody else has set a locking callback already. */
    if (CRYPTO_get_locking_callback())
        return;

    locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!locks)
        return;

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        if (pthread_mutex_init(&(locks[i]), NULL) != 0) {
            for (int n = 0; n < i; n++)
                pthread_mutex_destroy(&(locks[n]));
            OPENSSL_free(locks);
            locks = NULL;
            return;
        }
    }

    CRYPTO_set_locking_callback(locking_cb);
    CRYPTO_THREADID_set_callback(thread_id_cb);
}

#endif /* OpenSSL < 1.1.0 */
