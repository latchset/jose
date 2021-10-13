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

#include <string.h>
#include <ctype.h>

#ifdef _WIN32
static const char *
jwe_getpass(const char *prompt)
{
    static char pwd[4096];

    fprintf(stdout, "%s", prompt);

    memset(pwd, 0, sizeof(pwd));
    for (size_t i = 0; i < sizeof(pwd) - 1; i++) {
        int c = fgetc(stdin);
        if (c == EOF || !isprint(c) || isspace(c))
            break;

        pwd[i] = c;
    }

    return pwd;
}
#else
#include <termios.h>
static const char *
jwe_getpass(const char *prompt)
{
    static char pwd[4096];
    struct termios of, nf;
    FILE *tty = NULL;

    tty = fopen("/dev/tty", "r+");
    if (!tty)
        return NULL;

    tcgetattr(fileno(tty), &of);
    nf = of;
    nf.c_lflag &= ~ECHO;
    nf.c_lflag |= ECHONL;

    if (tcsetattr(fileno(tty), TCSANOW, &nf) != 0) {
        fclose(tty);
        return NULL;
    }

    fprintf(tty, "%s", prompt);

    memset(pwd, 0, sizeof(pwd));
    for (size_t i = 0; i < sizeof(pwd) - 1; i++) {
        int c = fgetc(tty);
        if (c == EOF || !isprint(c) || isspace(c))
            break;

        pwd[i] = c;
    }

    tcsetattr(fileno(tty), TCSANOW, &of);
    fclose(tty);
    return pwd;
}
#endif
