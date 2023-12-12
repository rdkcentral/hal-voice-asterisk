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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dm_handler.h"
#include "conf_mng.h"
#include "process_mng.h"
#include "cmd_intf.h"
#include "log.h"

#define DM_OBJ_VOICE_SERVICE "Device.Services.VoiceService."
#define DM_OBJ_VOICE_SERVICE_1 DM_OBJ_VOICE_SERVICE "1."
#define DM_OBJ_VOICE_SIP DM_OBJ_VOICE_SERVICE_1 "SIP."
#define DM_OBJ_VOICE_SIP_CLIENT DM_OBJ_VOICE_SIP "Client."
#define DM_OBJ_VOICE_SIP_CLIENT_1 DM_OBJ_VOICE_SIP_CLIENT "1."
#define DM_PARAM_SIP_CLIENT_AUTH_USER_NAME DM_OBJ_VOICE_SIP_CLIENT_1 \
    "AuthUserName"
#define DM_PARAM_SIP_CLIENT_AUTH_PASSWORD DM_OBJ_VOICE_SIP_CLIENT_1 \
    "AuthPassword"
#define DM_PARAM_SIP_CLIENT_ENABLE DM_OBJ_VOICE_SIP_CLIENT_1 \
    "Enable"
#define DM_PARAM_SIP_CLIENT_STATUS DM_OBJ_VOICE_SIP_CLIENT_1 \
    "Status"

#define DM_OBJ_VOICE_SIP_NETWORK DM_OBJ_VOICE_SIP "Network."
#define DM_OBJ_VOICE_SIP_NETWORK_1 DM_OBJ_VOICE_SIP_NETWORK "1."

#define DM_PARAM_NETWORK_OUTBOUND_PROXY DM_OBJ_VOICE_SIP_NETWORK_1 \
    "OutboundProxy"
#define DM_PARAM_NETWORK_OUTBOUND_PROXY_PORT DM_OBJ_VOICE_SIP_NETWORK_1 \
    "OutboundProxyPort"

typedef int (*set_func_t)(char *value);
typedef int (*get_func_t)(char *req_name, dm_resp_cb_t resp_cb, void *context);

typedef struct
{
    char *name;
    set_func_t set;
    get_func_t get;
} dm_param_t;

static int dm_param_proxy_server_set(char *value)
{
    return conf_sip_proxy_server_set(value);
}

static int dm_param_proxy_server_get(char *req_name, dm_resp_cb_t resp_cb,
    void *context)
{
    int ret;
    char *proxy_server = conf_sip_proxy_server_get();

    ret = resp_cb(DM_PARAM_NETWORK_OUTBOUND_PROXY, proxy_server ? proxy_server : "",
        DM_PARAM_STRING, context);

    free(proxy_server);

    return ret;
}

static int dm_param_proxy_server_port_set(char *value)
{
    return conf_sip_proxy_port_set(atoi(value));
}

static int dm_param_proxy_server_port_get(char *req_name, dm_resp_cb_t resp_cb,
    void *context)
{
    char str_port_buf[6];
    uint16_t proxy_server_port = conf_sip_proxy_server_port_get();

    snprintf(str_port_buf, sizeof(str_port_buf), "%u", proxy_server_port);

    return resp_cb(DM_PARAM_NETWORK_OUTBOUND_PROXY_PORT, str_port_buf,
        DM_PARAM_UNSIGNED_INTEGER, context);
}

static int dm_param_sip_username_set(char *value)
{
    return conf_sip_username_set(value);
}

static int dm_param_sip_username_get(char *req_name, dm_resp_cb_t resp_cb,
    void *context)
{
    int ret;
    char *username = conf_sip_username_get();

    ret = resp_cb(DM_PARAM_SIP_CLIENT_AUTH_USER_NAME, username ? username : "",
        DM_PARAM_STRING, context);

    free(username);

    return ret;
}

static int dm_param_sip_password_set(char *value)
{
    return conf_sip_password_set(value);
}

static int dm_param_sip_password_get(char *req_name, dm_resp_cb_t resp_cb,
    void *context)
{
    int ret;
    char *password = conf_sip_password_get();

    ret = resp_cb(DM_PARAM_SIP_CLIENT_AUTH_PASSWORD, password ? password : "",
        DM_PARAM_STRING, context);

    free(password);

    return ret;
}

static int dm_param_status_get(char *req_name, dm_resp_cb_t resp_cb,
    void *context)
{
    int ret;
    cmd_sip_reg_status_t reg_status;
    int enabled =  conf_sip_enabled_get();
    char *username = conf_sip_username_get();
    char *proxy_server = conf_sip_proxy_server_get();

    if (!enabled)
    {
        ret = resp_cb(DM_PARAM_SIP_CLIENT_STATUS, "Disabled", DM_PARAM_STRING,
            context);
        goto Exit;
    }

    if (username == NULL || proxy_server == NULL)
    {
        ret = resp_cb(DM_PARAM_SIP_CLIENT_STATUS, "Error", DM_PARAM_STRING,
            context);
        goto Exit;
    }

    if ((ret = cmd_sip_registration_get(username, proxy_server, &reg_status))
        == -1)
    {
        goto Exit;
    }

    switch (reg_status)
    {
    case SIP_REG_UNREGISTERED:
        ret = resp_cb(DM_PARAM_SIP_CLIENT_STATUS, "Registering", DM_PARAM_STRING,
            context);
        break; 
    case SIP_REG_REGISTERED:
        ret = resp_cb(DM_PARAM_SIP_CLIENT_STATUS, "Up", DM_PARAM_STRING, context);
        break;    
    case SIP_REG_REJECTED:
        ret = resp_cb(DM_PARAM_SIP_CLIENT_STATUS, "Error", DM_PARAM_STRING, context);
        break;
    case SIP_REG_NOT_FOUND:
        ret = resp_cb(DM_PARAM_SIP_CLIENT_STATUS, "Initializing", DM_PARAM_STRING,
            context);
        break;
    default:
        ret = -1;
        break;
    }

Exit:
    free(proxy_server);
    free(username);

    return ret;
}

static int dm_param_enable_get(char *req_name, dm_resp_cb_t resp_cb,
    void *context)
{
    int ret;
    int enabled = conf_sip_enabled_get();

    ret = resp_cb(DM_PARAM_SIP_CLIENT_ENABLE, enabled ? "1" : "0",
        DM_PARAM_STRING, context);

    return ret;
}

static int dm_param_enable_set(char *value)
{
    return conf_sip_enabled_set(!strcmp(value, "1"));
}

static dm_param_t params[] =
{
    { DM_PARAM_NETWORK_OUTBOUND_PROXY, dm_param_proxy_server_set,
        dm_param_proxy_server_get },
    { DM_PARAM_NETWORK_OUTBOUND_PROXY_PORT, dm_param_proxy_server_port_set, 
        dm_param_proxy_server_port_get },
    { DM_PARAM_SIP_CLIENT_AUTH_USER_NAME, dm_param_sip_username_set,
        dm_param_sip_username_get },
    { DM_PARAM_SIP_CLIENT_AUTH_PASSWORD, dm_param_sip_password_set,
        dm_param_sip_password_get },
    { DM_PARAM_SIP_CLIENT_STATUS, NULL, dm_param_status_get },
    { DM_PARAM_SIP_CLIENT_ENABLE, dm_param_enable_set, dm_param_enable_get },
};

int dm_param_set(char *name, char *value, dm_param_type_t type)
{
    int i;

    for (i = 0; i < sizeof(params) / sizeof(params[0]); i++)
    {
        if (strcmp(params[i].name, name))
        {
            continue;
        }

        if (params[i].set == NULL)
        {
            return -1;
        }
        
        if (params[i].set(value) == -1)
        {
            return -1;
        }

        return process_reconf();
    }

    return 0;
}


int dm_param_get(char *req_name, dm_resp_cb_t resp_cb, void *context)
{
    int i;

    /* Handle object request */
    if (!strcmp(req_name, DM_OBJ_VOICE_SERVICE) ||
        !strcmp(req_name, DM_OBJ_VOICE_SERVICE_1))
    {
        for (i = 0; i < sizeof(params) / sizeof(params[0]); i++)
        {
            if (params[i].get == NULL)
            {
                continue;
            }

            if (params[i].get(req_name, resp_cb, context) == -1)
            {
                return -1;
            }
        }

        return 0;
    }

    /* Handle parameter request */
    for (i = 0; i < sizeof(params) / sizeof(params[0]); i++)
    {
        if (strcmp(params[i].name, req_name))
        {
            continue;
        }

        if (params[i].get == NULL)
        {
            return -1;
        }

        if (params[i].get(req_name, resp_cb, context) == -1)
        {
            return -1;
        }

        return 0;
    }

    /* Ignore unsupported parameters */
    return 0;
}
