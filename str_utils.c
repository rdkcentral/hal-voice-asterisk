/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

char **str_printf(char **s, char *fmt, ...)
{
    int len, ret;
    va_list arg;

    *s = NULL;
    va_start(arg, fmt);
    ret = vsnprintf(NULL, 0, fmt, arg);
    va_end(arg);
    if (ret < 0)
    {
        goto Exit;
    }
    len = ret + 1;
    if (!(*s = malloc(len)))
    {
        goto Exit;
    }
    va_start(arg, fmt);
    ret = vsnprintf(*s, len, fmt, arg);
    va_end(arg);
    if (ret < 0)
    {
        free(*s);
        *s = NULL;
    }

Exit:
    return s;
}