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
#include <signal.h>
#include <stdlib.h>
#include "process_mng.h"
#include "conf_mng.h"
#include "cmd_intf.h"
#include "log.h"
#include "rpc_handler.h"

static void program_exit(int ret)
{
    rpc_handler_uninit();
    conf_uninit();
    process_stop();
    exit(ret);
}

static void sig_handler(int signum)
{
    program_exit(0);
}

static void signal_init()
{
    signal(SIGINT, sig_handler);
}

int main(int argc, char *argv[])
{
    signal_init();
    
    if (conf_init() == -1)
    {
        return -1;
    }

    if (process_start() == -1)
    {
        goto Error;
    }

    if (rpc_handler_init() == -1)
    {
        goto Error;
    }

    while (1)
    {
        sleep(1);
    }

    return 0;

Error:
    program_exit(-1);
    return -1;
}