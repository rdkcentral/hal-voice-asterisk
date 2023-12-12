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

#ifndef CONF_MNG_H
#define CONF_MNG_H

#include <stdint.h>

#define ASTERISK_CONF_PATH "/var/asterisk"
#define ASTERISK_CONF_PATH_ASTERISK ASTERISK_CONF_PATH "/asterisk.conf"
#define ASTERISK_CONF_PATH_MODULES ASTERISK_CONF_PATH "/modules.conf"
#define ASTERISK_CONF_PATH_LOGGER ASTERISK_CONF_PATH "/logger.conf"
#define ASTERISK_CONF_PATH_PJSIP ASTERISK_CONF_PATH "/pjsip.conf"
#define ASTERISK_CONF_PATH_EXTENSIONS ASTERISK_CONF_PATH "/extensions.conf"

typedef struct {
    int enabled;
    char *proxy_server;
    uint16_t proxy_server_port;
    char *username;
    char *password;
} sip_conf_t;

int conf_init();
void conf_uninit();
int conf_sip_enabled_set(int enabled);
int conf_sip_enabled_get();
int conf_sip_proxy_server_set(char *proxy_server);
char *conf_sip_proxy_server_get();
int conf_sip_proxy_port_set(uint16_t proxy_server_port);
uint16_t conf_sip_proxy_server_port_get();
int conf_sip_username_set(char *username);
char *conf_sip_username_get();
int conf_sip_password_set(char *password);
char *conf_sip_password_get();

#endif
