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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "cmd_intf.h"
#include "log.h"
#include "process_utils.h"

#define ASTERISK_BIN "/usr/sbin/asterisk"
#define PJSIP_REG_STATUS_CMD "pjsip show registrations"

#define PJSIP_REG_ID_BUF_SIZE 55
#define PJSIP_REG_AUTH_BUF_SIZE 24
#define PJSIP_REG_STATUS_BUF_SIZE 32
#define PJSIP_REGISTRATION_LINE_FORMAT "%54s %23s %31s"
#define PJSIP_REGISTRATION_ID_FORMAT "%s/sip:%s"
#define PJSIP_REGISTRATION_STATUS_REGISTERED "Registered"
#define PJSIP_REGISTRATION_STATUS_UNREGISTERED "Unregistered"
#define PJSIP_REGISTRATION_STATUS_REJECTED "Rejected"

#define PJSIP_REG_STATUS_CMD_RESULT_SIZE 2048

static int cmd_sip_registration_result_read(int fd_out, char *buf,
    unsigned int buf_size)
{
    int ret;
    int pos = 0;
    int count = 0;

    while (count < buf_size)
    {
        ret = read(fd_out, buf + pos, buf_size - pos);
        if (ret == -1)
        {
            log_message(LERR, "Failed to read from process stdout, error %s\n",
                strerror(errno));
            return -1;
        }
        else if (ret == 0)
        {
            return count;
        }
        else
        {
            pos += ret;
            count += ret;
        }
    }

    log_message(LWARNING, "Command result buffer overflow\n");
    buf[count - 1] = '\0';
    return count;
}

static int cmd_sip_registration_parse(char *buf, unsigned int len,
    char *username, char *proxy_server, cmd_sip_reg_status_t *reg_status)
{
    int ret;
    char *line_end;
    char reg_id_search_buf[PJSIP_REG_ID_BUF_SIZE];
    char reg_id_buf[PJSIP_REG_ID_BUF_SIZE];
    char reg_auth_buf[PJSIP_REG_AUTH_BUF_SIZE];
    char reg_status_buf[PJSIP_REG_STATUS_BUF_SIZE];
    char *str = buf;

    /* Create search registration ID: Registration/ServerURI */
    ret = snprintf(reg_id_search_buf, sizeof(reg_id_search_buf),
        PJSIP_REGISTRATION_ID_FORMAT, username, proxy_server);
    if (ret >= sizeof(reg_id_search_buf) || ret < 0)
    {
        log_message(LERR, "Failed to create registration ID");
        return -1;
    }

    while (str < buf + len)
    {
        /* Select line separated by \n */
        line_end = strstr(str, "\n");
        if (!line_end)
            return -1;
        *line_end = '\0';

        /* Scan registration line: <Registration/ServerURI> <Auth> <Status> */
        ret = sscanf(str, PJSIP_REGISTRATION_LINE_FORMAT, reg_id_buf,
            reg_auth_buf, reg_status_buf);
        str = line_end + 1;
        if (ret < 3)
        {
            continue;
        }

        /* Match Registration/ServerURI */
        if (strncmp(reg_id_search_buf, reg_id_buf, sizeof(reg_id_buf)))
        {
            continue;
        }

        /* Match Auth */
        if (strncmp(username, reg_auth_buf, sizeof(reg_auth_buf)))
        {
            continue;
        }

        /* Check state */
        if (!strncmp(reg_status_buf, PJSIP_REGISTRATION_STATUS_REGISTERED,
            sizeof(reg_status_buf)))
        {
            *reg_status = SIP_REG_REGISTERED;
            return 0;
        }

        if (!strncmp(reg_status_buf, PJSIP_REGISTRATION_STATUS_UNREGISTERED,
            sizeof(reg_status_buf)))
        {
            *reg_status = SIP_REG_UNREGISTERED;
            return 0;
        }

        if (!strncmp(reg_status_buf, PJSIP_REGISTRATION_STATUS_REJECTED,
            sizeof(reg_status_buf)))
        {
            *reg_status = SIP_REG_REJECTED;
            return 0;
        }
    }

    *reg_status = SIP_REG_NOT_FOUND;
    return 0;
}

int cmd_sip_registration_get(char *username, char *proxy_server,
    cmd_sip_reg_status_t *reg_status)
{
    int ret;
    pid_t pid;
    int fd_out;
    char res_buf[PJSIP_REG_STATUS_CMD_RESULT_SIZE] = {};
    char *const argv[] = { ASTERISK_BIN, "-x", PJSIP_REG_STATUS_CMD,
        NULL };

    if (process_execute(ASTERISK_BIN, argv, &pid, NULL, &fd_out,
        NULL) == -1)
    {
        return -1;
    }

    ret = cmd_sip_registration_result_read(fd_out, res_buf, sizeof(res_buf));
    if (ret == -1)
    {
        return -1;
    }

    if (cmd_sip_registration_parse(res_buf, ret, username, proxy_server,
        reg_status) == -1)
    {
        return -1;
    }

    return process_terminate(pid);
}
