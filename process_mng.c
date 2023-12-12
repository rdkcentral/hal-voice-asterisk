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
#include <signal.h>
#include <unistd.h>
#include "process_utils.h"
#include "log.h"
#include "conf_mng.h"

#define ASTERISK_BIN "/usr/sbin/asterisk"
#define RECONF_DELAY_SEC 3

static pid_t g_pid = -1;

int process_start()
{
    char *const argv[] = { ASTERISK_BIN, "-f", "-C", ASTERISK_CONF_PATH_ASTERISK, NULL };

    return process_execute(ASTERISK_BIN, argv, &g_pid, NULL, NULL, NULL);
}

int process_stop()
{
    int ret;

    if (g_pid == -1)
    {
        return 0;
    }

    /* Cancel pending reconfiguration */
    alarm(0);

    ret = process_terminate(g_pid);
    g_pid = -1;

    return ret;
}

int process_restart()
{
    if (process_stop() == -1)
        return -1;
    return process_start();
}

static void sig_handler(int signum)
{
    if (g_pid == -1)
    {
        return;
    }

    kill(g_pid, SIGHUP);
}

int process_reconf()
{
    if (g_pid == -1)
    {
        return -1;
    }

    /* Aggregate multiple changes before reconfiguration */
    if (signal(SIGALRM, sig_handler) == SIG_ERR)
    {
        log_message(LERR, "Failed to set SIGALRM handler\n");
        return -1;
    }
    alarm(0);
    alarm(RECONF_DELAY_SEC);

    return 0;
}
