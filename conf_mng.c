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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "log.h"
#include "conf_mng.h"
#include "str_utils.h"

#define DEFAULT_SIP_PORT 5060

#define ASTERISK_CONF \
    "[directories](!)\n" \
    "astcachedir => /tmp\n" \
    "astetcdir => "ASTERISK_CONF_PATH"\n" \
    "astmoddir => /usr/lib/asterisk/modules\n" \
    "astvarlibdir => /var/lib/asterisk\n" \
    "astdbdir => /var/lib/asterisk\n" \
    "astkeydir => /var/lib/asterisk\n" \
    "astdatadir => /usr/share/asterisk\n" \
    "astagidir => /usr/share/asterisk/agi-bin\n" \
    "astspooldir => /var/spool/asterisk\n" \
    "astrundir => /var/run/asterisk\n" \
    "astlogdir => /var/log/asterisk\n" \
    "astsbindir => /usr/sbin\n"

#define MODULES_CONF \
    "[modules]\n" \
    "autoload=yes\n"

#define LOGGER_CONF \
    "[general]\n" \
    "[logfiles]\n" \
    "console => notice,warning,error\n" \
    "messages => notice,warning,error\n"

#define ASTERISK_EXTENSION_1 "601"
#define ASTERISK_EXTENSION_2 "602"

#define ASTERISK_CONF_PJSIP_TRANSPORT \
    "[udp-transport]\n" \
    "type=transport\n" \
    "protocol=udp\n" \
    "bind=0.0.0.0\n" \
    "\n"

#define ASTERISK_CONF_PJSIP_OUTBOUND_REGISTRATION \
    "[%s]\n" \
    "type=registration\n" \
    "transport=udp-transport\n" \
    "outbound_auth=%s\n" \
    "server_uri=sip:%s%s\n" \
    "client_uri=sip:%s@%s%s\n" \
    "retry_interval=60\n" \
    "expiration=120\n" \
    "contact_user=%s\n" \
    "\n"

#define ASTERISK_CONF_PJSIP_OUTBOUND_AUTH \
    "[%s]\n" \
    "type=auth\n" \
    "auth_type=userpass\n" \
    "username=%s\n" \
    "password=%s\n" \
    "\n"

#define ASTERISK_CONF_PJSIP_OUTBOUND_AOR \
    "[%s]\n" \
    "type=aor\n" \
    "contact=sip:%s%s\n" \
    "\n"

#define ASTERISK_CONF_PJSIP_OUTBOUND_ENDPOINT \
    "[%s]\n" \
    "type=endpoint\n" \
    "transport=udp-transport\n" \
    "context=from-external\n" \
    "disallow=all\n" \
    "allow=alaw\n" \
    "allow=ulaw\n" \
    "outbound_auth=%s\n" \
    "aors=%s\n" \
    "from_user=%s\n" \
    "direct_media=no\n" \
    "\n"

#define ASTERISK_CONF_PJSIP_OUTBOUND_IDENTIFY \
    "[%s]\n" \
    "type=identify\n" \
    "endpoint=%s\n" \
    "match=%s\n" \
    "\n"

#define ASTERISK_CONF_PJSIP_INBOUND_REGISTRATION \
    "[%s]\n" \
    "type=endpoint\n" \
    "transport=udp-transport\n" \
    "context=from-internal\n" \
    "disallow=all\n" \
    "allow=alaw\n" \
    "allow=ulaw\n" \
    "auth=%s\n" \
    "aors=%s\n" \
    "direct_media=no\n" \
    "\n" \
    "[%s]\n" \
    "type=auth\n" \
    "auth_type=userpass\n" \
    "password=%s\n" \
    "username=%s\n" \
    "\n" \
    "[%s]\n" \
    "type=aor\n" \
    "max_contacts=10\n" \
    "\n"

#define ASTERISK_CONF_EXTENSIONS_FROM_EXTERNAL \
    "[from-external]\n" \
    "exten => %s,1,Dial(PJSIP/%s&PJSIP/%s)\n" \
    "\n"

#define ASTERISK_CONF_EXTENSIONS_FROM_INTERNAL \
    "[from-internal]\n" \
    "exten => _XXX,1,Dial(PJSIP/${EXTEN})\n"

#define ASTERISK_CONF_EXTENSIONS_FROM_INTERNAL_OUTGOING \
    "exten => _X.,1,Dial(PJSIP/${EXTEN}@%s)\n"

static sip_conf_t g_sip_conf = {};

static int conf_write_asterisk()
{
    FILE *file;
    int ret = -1;
    
    if ((file = fopen(ASTERISK_CONF_PATH_ASTERISK, "w")) == NULL)
    {
        log_message(LERR, "Failed to open %s for write, error %s\n",
            ASTERISK_CONF_PATH_ASTERISK, strerror(errno));
        return -1;
    }

    if (fprintf(file, ASTERISK_CONF) < 0)
    {
        log_message(LERR, "Failed to write %s\n",
            ASTERISK_CONF_PATH_ASTERISK);
        goto Exit;
    }

    ret = 0;
Exit:
    if (fclose(file) == EOF)
    {
        log_message(LERR, "Failed to close %s\n",
            ASTERISK_CONF_PATH_ASTERISK);
        return -1;
    }
    return ret;
}

static int conf_write_modules()
{
    FILE *file;
    int ret = -1;
    
    if ((file = fopen(ASTERISK_CONF_PATH_MODULES, "w")) == NULL)
    {
        log_message(LERR, "Failed to open %s for write, error %s\n",
            ASTERISK_CONF_PATH_MODULES, strerror(errno));
        return -1;
    }

    if (fprintf(file, MODULES_CONF) < 0)
    {
        log_message(LERR, "Failed to write %s\n",
            ASTERISK_CONF_PATH_MODULES);
        goto Exit;
    }

    ret = 0;
Exit:
    if (fclose(file) == EOF)
    {
        log_message(LERR, "Failed to close %s\n",
            ASTERISK_CONF_PATH_MODULES);
        return -1;
    }
    return ret;
}

static int conf_write_logger()
{
    FILE *file;
    int ret = -1;
    
    if ((file = fopen(ASTERISK_CONF_PATH_LOGGER, "w")) == NULL)
    {
        log_message(LERR, "Failed to open %s for write, error %s\n",
            ASTERISK_CONF_PATH_LOGGER, strerror(errno));
        return -1;
    }

    if (fprintf(file, LOGGER_CONF) < 0)
    {
        log_message(LERR, "Failed to write %s\n",
            ASTERISK_CONF_PATH_LOGGER);
        goto Exit;
    }

    ret = 0;
Exit:
    if (fclose(file) == EOF)
    {
        log_message(LERR, "Failed to close %s\n",
            ASTERISK_CONF_PATH_LOGGER);
        return -1;
    }
    return ret;
}

static int conf_write_pjsip_transport(FILE *file)
{
    if (fputs(ASTERISK_CONF_PJSIP_TRANSPORT, file) == EOF)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        return -1;
    }

    return 0;
}

static int conf_write_pjsip_outbound_registration(FILE *file,
    sip_conf_t *sip_conf)
{
    int ret = -1;
    char *conf_str = NULL;
    char port_str[7] = {};

    if (sip_conf->proxy_server == NULL || sip_conf->username == NULL)
        return 0;

    if (sip_conf->proxy_server_port &&
        sip_conf->proxy_server_port != DEFAULT_SIP_PORT)
    {
        snprintf(port_str, sizeof(port_str), ":%u",
            sip_conf->proxy_server_port);
    }

    if (str_printf(&conf_str, ASTERISK_CONF_PJSIP_OUTBOUND_REGISTRATION,
        sip_conf->username, sip_conf->username, sip_conf->proxy_server,
        port_str, sip_conf->username, sip_conf->proxy_server, port_str,
        sip_conf->username) == NULL)
    {
        log_message(LERR, "Failed to allocate string for asterisk outbound "
            "registration\n");
        return -1;
    }

    if (fputs(conf_str, file) == EOF)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        goto Exit;
    }

    ret = 0;
Exit:
    free(conf_str);
    return ret;
}

static int conf_write_pjsip_outbound_auth(FILE *file, sip_conf_t *sip_conf)
{
    int ret = -1;
    char *conf_str = NULL;

    if (sip_conf->username == NULL || sip_conf->password == NULL)
        return 0;

    if (str_printf(&conf_str, ASTERISK_CONF_PJSIP_OUTBOUND_AUTH,
        sip_conf->username, sip_conf->username, sip_conf->password) == NULL)
    {
        log_message(LERR, "Failed to allocate string for asterisk outbound "
            "auth\n");
        return -1;
    }

    if (fputs(conf_str, file) == EOF)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        goto Exit;
    }

    ret = 0;
Exit:
    free(conf_str);
    return ret;
}

static int conf_write_pjsip_outbound_aor(FILE *file, sip_conf_t *sip_conf)
{
    int ret = -1;
    char *conf_str = NULL;
    char port_str[7] = {};

    if (sip_conf->proxy_server == NULL || sip_conf->username == NULL)
        return 0;

    if (sip_conf->proxy_server_port &&
        sip_conf->proxy_server_port != DEFAULT_SIP_PORT)
    {
        snprintf(port_str, sizeof(port_str), ":%u",
            sip_conf->proxy_server_port);
    }
    if (str_printf(&conf_str, ASTERISK_CONF_PJSIP_OUTBOUND_AOR,
        sip_conf->username, sip_conf->proxy_server, port_str) == NULL)
    {
        log_message(LERR, "Failed to allocate string for asterisk outbound "
            "aor\n");
        return -1;
    }

    if (fputs(conf_str, file) == EOF)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        goto Exit;
    }

    ret = 0;
Exit:
    free(conf_str);
    return ret;
}

static int conf_write_pjsip_outbound_endpoint(FILE *file, sip_conf_t *sip_conf)
{
    int ret = -1;
    char *conf_str = NULL;

    if (sip_conf->username == NULL)
        return 0;

    if (str_printf(&conf_str, ASTERISK_CONF_PJSIP_OUTBOUND_ENDPOINT,
        sip_conf->username, sip_conf->username, sip_conf->username,
        sip_conf->username) == NULL)
    {
        log_message(LERR, "Failed to allocate string for asterisk outbound "
            "enpoint\n");
        return -1;
    }

    if (fputs(conf_str, file) == EOF)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        goto Exit;
    }

    ret = 0;
Exit:
    free(conf_str);
    return ret;
}

static int conf_write_pjsip_outbound_indentify(FILE *file,
    sip_conf_t *sip_conf)
{
    int ret = -1;
    char *conf_str = NULL;

    if (sip_conf->proxy_server == NULL || sip_conf->username == NULL)
        return 0;

    if (str_printf(&conf_str, ASTERISK_CONF_PJSIP_OUTBOUND_IDENTIFY,
        sip_conf->username, sip_conf->username, sip_conf->proxy_server)
        == NULL)
    {
        log_message(LERR, "Failed to allocate string for asterisk outbound "
            "identify\n");
        return -1;
    }

    if (fputs(conf_str, file) == EOF)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        goto Exit;
    }

    ret = 0;
Exit:
    free(conf_str);
    return ret;
}

static int conf_write_pjsip_outbound(FILE *file, sip_conf_t *sip_conf)
{
    if (sip_conf->enabled == 0)
        return 0;

    if (conf_write_pjsip_outbound_registration(file, sip_conf) == -1)
        return -1;

    if (conf_write_pjsip_outbound_auth(file, sip_conf) == -1)
        return -1;

    if (conf_write_pjsip_outbound_aor(file, sip_conf) == -1)
        return -1;

    if (conf_write_pjsip_outbound_endpoint(file, sip_conf) == -1)
        return -1;

    if (conf_write_pjsip_outbound_indentify(file, sip_conf) == -1)
        return -1;

    return 0;
}

static int conf_write_pjsip_inbound(FILE *file)
{
    /* Configure extension 1 inbound registration */
    if (fprintf(file, ASTERISK_CONF_PJSIP_INBOUND_REGISTRATION,
        ASTERISK_EXTENSION_1, ASTERISK_EXTENSION_1, ASTERISK_EXTENSION_1,
        ASTERISK_EXTENSION_1, ASTERISK_EXTENSION_1, ASTERISK_EXTENSION_1,
        ASTERISK_EXTENSION_1) < 0)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        return -1;
    }

    /* Configure extension 2 inbound registration */
    if (fprintf(file, ASTERISK_CONF_PJSIP_INBOUND_REGISTRATION,
        ASTERISK_EXTENSION_2, ASTERISK_EXTENSION_2, ASTERISK_EXTENSION_2,
        ASTERISK_EXTENSION_2, ASTERISK_EXTENSION_2, ASTERISK_EXTENSION_2,
        ASTERISK_EXTENSION_2) < 0)
    {
        log_message(LERR, "Failed to write %s\n", ASTERISK_CONF_PATH_PJSIP);
        return -1;
    }

    return 0;
}

static int conf_write_pjsip(sip_conf_t *sip_conf)
{
    FILE *file;
    int ret = -1;
    
    file = fopen(ASTERISK_CONF_PATH_PJSIP, "w");
    if (!file)
    {
        log_message(LERR, "Failed to open %s for write, error %s\n",
            ASTERISK_CONF_PATH_PJSIP, strerror(errno));
        return -1;
    }

    /* transport configuration */
    if (conf_write_pjsip_transport(file) == -1)
        goto Exit;

    /* outbound registration configuration */
    if (conf_write_pjsip_outbound(file, sip_conf) == -1)
        goto Exit;

    /* inbound registration configuration */
    if (conf_write_pjsip_inbound(file) == -1)
        goto Exit;

    ret = 0;
Exit:
    if (fclose(file) == EOF)
    {
        log_message(LERR, "Failed to close %s\n", ASTERISK_CONF_PATH_PJSIP);
        return -1;
    }
    return ret;
}

static int conf_write_extensions(sip_conf_t *sip_conf)
{
    FILE *file;
    int ret = -1;
    
    if ((file = fopen(ASTERISK_CONF_PATH_EXTENSIONS, "w")) == NULL)
    {
        log_message(LERR, "Failed to open %s for write, error %s\n",
            ASTERISK_CONF_PATH_EXTENSIONS, strerror(errno));
        return -1;
    }

    /* Configure incoming call to ring on first extension */
    if (sip_conf->enabled && sip_conf->username != NULL &&
        fprintf(file, ASTERISK_CONF_EXTENSIONS_FROM_EXTERNAL,
        sip_conf->username, ASTERISK_EXTENSION_1, ASTERISK_EXTENSION_2) < 0)
    {
        log_message(LERR, "Failed to write %s\n",
            ASTERISK_CONF_PATH_EXTENSIONS);
        goto Exit;
    }

    /* Configure calls between extensions */
    if (fprintf(file, ASTERISK_CONF_EXTENSIONS_FROM_INTERNAL) < 0)
    {
        log_message(LERR, "Failed to write %s\n",
            ASTERISK_CONF_PATH_EXTENSIONS);
        goto Exit;
    }

    /* Configure outgoing call */
    if (sip_conf->enabled && sip_conf->username != NULL &&
        fprintf(file, ASTERISK_CONF_EXTENSIONS_FROM_INTERNAL_OUTGOING,
        sip_conf->username) < 0)
    {
        log_message(LERR, "Failed to write %s\n",
            ASTERISK_CONF_PATH_EXTENSIONS);
        goto Exit;
    }

    ret = 0;
Exit:
    if (fclose(file) == EOF)
    {
        log_message(LERR, "Failed to close %s\n",
            ASTERISK_CONF_PATH_EXTENSIONS);
        return -1;
    }
    return ret;
}

static int conf_set(sip_conf_t *sip_conf)
{
    if (conf_write_asterisk() == -1)
        return -1;

    if (conf_write_modules() == -1)
        return -1;

    if (conf_write_logger() == -1)
        return -1;

    if (conf_write_pjsip(sip_conf) == -1)
        return -1;

    if (conf_write_extensions(sip_conf) == -1)
        return -1;

    return 0;
}

int conf_init()
{
    mkdir(ASTERISK_CONF_PATH, 0644);
    return conf_set(&g_sip_conf);
}

void conf_uninit()
{
    g_sip_conf.enabled = 0;
    free(g_sip_conf.proxy_server);
    g_sip_conf.proxy_server = NULL;
    g_sip_conf.proxy_server_port = 0;
    free(g_sip_conf.username);
    g_sip_conf.username = NULL;
    free(g_sip_conf.password);
    g_sip_conf.password = NULL;
}

int conf_sip_enabled_set(int enabled)
{
    g_sip_conf.enabled = enabled;

    return conf_set(&g_sip_conf);
}

int conf_sip_enabled_get()
{
    return g_sip_conf.enabled;
}

int conf_sip_proxy_server_set(char *proxy_server)
{
    free(g_sip_conf.proxy_server);
    g_sip_conf.proxy_server = strdup(proxy_server ? proxy_server : "");
    
    return conf_set(&g_sip_conf);
}

char *conf_sip_proxy_server_get()
{
    return g_sip_conf.proxy_server ? strdup(g_sip_conf.proxy_server) : NULL;
}

int conf_sip_proxy_port_set(uint16_t proxy_server_port)
{
    g_sip_conf.proxy_server_port = proxy_server_port;
    
    return conf_set(&g_sip_conf);
}

uint16_t conf_sip_proxy_server_port_get()
{
    return g_sip_conf.proxy_server_port;
}

int conf_sip_username_set(char *username)
{
    free(g_sip_conf.username);
    g_sip_conf.username = strdup(username ? username : "");
    
    return conf_set(&g_sip_conf);
}

char *conf_sip_username_get()
{
    return g_sip_conf.username ? strdup(g_sip_conf.username) : NULL;
}

int conf_sip_password_set(char *password)
{
    free(g_sip_conf.password);
    g_sip_conf.password = strdup(password ? password : "");
    
    return conf_set(&g_sip_conf);
}

char *conf_sip_password_get()
{
    return g_sip_conf.password ? strdup(g_sip_conf.password) : NULL;
}
