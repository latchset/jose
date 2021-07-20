/*
 * Copyright 2021 Red Hat, Inc.
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

#ifndef __JOSE_LOG__
#define __JOSE_LOG__

#ifdef __PRINTF_ERR__
#define jose_logerr(...) printf (__VA_ARGS__)
#elsif
#ifdef __SYSLOG__
#define jose_logerr(...) // TODO: dump log to syslog
#endif
#else
#define jose_logerr(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifdef __SYSLOG__
#define jose_output(...) // TODO: dump log to syslog
#else
#define jose_output(...) fprintf(stdout, __VA_ARGS__)
#endif


#endif // __JOSE_LOG__
