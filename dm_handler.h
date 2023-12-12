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

#ifndef DM_HANDLER_H
#define DM_HANDLER_H

typedef enum param_type
{
    DM_PARAM_BOOLEAN = 1,
    DM_PARAM_STRING,
    DM_PARAM_INTEGER,
    DM_PARAM_UNSIGNED_INTEGER,
    DM_PARAM_LONG,
    DM_PARAM_UNSIGNED_LONG,
    DM_PARAM_HEXBINARY,
    DM_PARAM_BASE64
} dm_param_type_t;

typedef int (*dm_resp_cb_t)(char *resp_name, char *resp_value,
    dm_param_type_t dm_type, void *context);

int dm_param_set(char *name, char *value, dm_param_type_t type);
int dm_param_get(char *req_name, dm_resp_cb_t resp_cb, void *context);

#endif
