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

#include <string.h>
#include <json_hal_server.h>
#include "log.h"
#include "dm_handler.h"

#define TELCOVOICEMGR_CONF_FILE "/etc/rdk/conf/telcovoice_manager_conf.json"

typedef struct
{
    eParamType rpc_type;
    dm_param_type_t dm_type;
} param_type_rpc_to_dm_t;

static param_type_rpc_to_dm_t param_type_rpc_to_dm[] =
{
    { PARAM_BOOLEAN, DM_PARAM_BOOLEAN },
    { PARAM_STRING, DM_PARAM_STRING },
    { PARAM_INTEGER, DM_PARAM_INTEGER },
    { PARAM_UNSIGNED_INTEGER, DM_PARAM_UNSIGNED_INTEGER },
    { PARAM_LONG, DM_PARAM_LONG },
    { PARAM_UNSIGNED_LONG, DM_PARAM_UNSIGNED_LONG },
    { PARAM_HEXBINARY, DM_PARAM_HEXBINARY },
    { PARAM_BASE64, DM_PARAM_BASE64 },
};

static dm_param_type_t rpc_to_dm_type(eParamType rpc_param_type)
{
    int i;

    for (i = 0; i < sizeof(param_type_rpc_to_dm) /
        sizeof(param_type_rpc_to_dm[0]); i++)
    {
        if (param_type_rpc_to_dm[i].rpc_type == rpc_param_type)
            return param_type_rpc_to_dm[i].dm_type;
    }

    return -1;
}

static eParamType dm_to_rpc_type(dm_param_type_t dm_type)
{
    int i;

    for (i = 0; i < sizeof(param_type_rpc_to_dm) /
        sizeof(param_type_rpc_to_dm[0]); i++)
    {
        if (param_type_rpc_to_dm[i].dm_type == dm_type)
            return param_type_rpc_to_dm[i].rpc_type;
    }

    return -1;
}

static int setparam_rpc_cb(const json_object *jmsg, int param_count,
    json_object *jreply)
{
    int i;
    int ret;
    hal_param_t param;
    dm_param_type_t type;

    if (jmsg == NULL || jreply == NULL)
    {
        log_message(LERR, "setParameters cb: invalid memory\n");
        return RETURN_ERR;
    }

    for (i = 0; i < param_count; i++)
    {
        /* Unpack the JSON and polulate the data into request_param object */
        if (json_hal_get_param((json_object *)jmsg, i, SET_REQUEST_MESSAGE,
            &param) != RETURN_OK)
        {
            log_message(LERR, "setParameters cb: failed get parameter\n");
            return RETURN_ERR;
        }

        /* Check and convert RPC parameter type to DM type */
        if ((type = rpc_to_dm_type(param.type)) == -1)
        {
            log_message(LERR, "setParameters cb: wrong parameter type\n");
            return RETURN_ERR;
        }

        /* Call parameter handler */
        ret = dm_param_set(param.name, param.value, type);

        /* Pack the json response and reply back. */
        if (json_hal_add_result_status(jreply, ret == 0 ? RESULT_SUCCESS :
            RESULT_FAILURE) != RETURN_OK)
        {
            log_message(LERR, "setParameters cb: failed to set status\n");
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

static int resp_cb(char *resp_name, char *resp_value, dm_param_type_t dm_type,
    void *context)
{
    hal_param_t param_response;
    json_object *jreply = context;

    strncpy(param_response.name, resp_name, sizeof(param_response.name));
    strncpy(param_response.value, resp_value, sizeof(param_response.value));

    if ((param_response.type = dm_to_rpc_type(dm_type)) == -1)
    {
        log_message(LERR, "response cb: wrong parameter type\n");
        return -1;
    }

    if (json_hal_add_param(jreply, GET_RESPONSE_MESSAGE, &param_response)
        != RETURN_OK)
    {
        log_message(LERR, "response cb: failed to add response\n");
        return -1;
    }

    return 0;
}

static int getparam_rpc_cb(const json_object *jmsg, int param_count,
    json_object *jreply)
{
    int i;
    hal_param_t param_request;

    if (jmsg == NULL || jreply == NULL)
    {
        log_message(LERR, "getParameters cb: invalid memory\n");
        return RETURN_ERR;
    }

    for (i = 0; i < param_count; i++)
    {
        /* Unpack the JSON and polulate the data into request_param object */
        if (json_hal_get_param((json_object *)jmsg, i, GET_REQUEST_MESSAGE,
            &param_request) != RETURN_OK)
        {
            log_message(LERR, "getParameters cb: failed get parameter\n");
            return RETURN_ERR;
        }

        /* Call parameter handler */
        if ((dm_param_get(param_request.name, resp_cb, jreply)) == -1)
        {
            log_message(LERR, "getParameters cb: failed get parameter\n");
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

static int subs_event_cb(const json_object *jmsg, int param_count,
    json_object *jreply)
{
    if (jmsg == NULL || jreply == NULL)
    {
        log_message(LERR, "subscribeEvent cb: invalid memory\n");
        return RETURN_ERR;
    }

    /* No supported events */

    if (json_hal_add_result_status(jreply, RESULT_SUCCESS) != RETURN_OK)
    {
        log_message(LERR, "subscribeEvent cb: failed to set status\n");
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int rpc_handler_init()
{
    if (json_hal_server_init(TELCOVOICEMGR_CONF_FILE) != RETURN_OK)
    {
        log_message(LERR, "Failed to init HAL server\n");
        return -1;
    }

    if (json_hal_server_register_action_callback("setParameters",
        setparam_rpc_cb) != RETURN_OK)
    {
        log_message(LERR, "Failed to register setParameters callback\n");
        goto Error;
    }

    if (json_hal_server_register_action_callback("getParameters",
        getparam_rpc_cb) != RETURN_OK)
    {
        log_message(LERR, "Failed to register getParameters callback\n");
        goto Error;
    }

    if (json_hal_server_register_action_callback("subscribeEvent",
        subs_event_cb) != RETURN_OK)
    {
        log_message(LERR, "Failed to register subscribeEvent callback\n");
        goto Error;
    }

    if (json_hal_server_run() != RETURN_OK)
    {
        log_message(LERR, "Failed to run HAL server\n");
        goto Error;
    }

    return 0;

Error:
    json_hal_server_terminate();
    return -1;
}

int rpc_handler_uninit()
{
    if (json_hal_server_terminate() != RETURN_OK)
    {
        log_message(LERR, "Failed to terminate HAL server\n");
        return -1;
    }

    return 0;
}
