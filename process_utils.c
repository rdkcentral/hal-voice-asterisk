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

#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "process_utils.h"
#include "log.h"

#define PIPE_READ_ENDPOINT 0
#define PIPE_WRITE_ENDPOINT 1

static void pipes_close(int pipe_in[], int pipe_out[], int pipe_err[])
{
    if (pipe_in[PIPE_READ_ENDPOINT] != -1)
        close(pipe_in[PIPE_READ_ENDPOINT]);
    if (pipe_in[PIPE_WRITE_ENDPOINT] != -1)
        close(pipe_in[PIPE_WRITE_ENDPOINT]);
    if (pipe_out[PIPE_READ_ENDPOINT] != -1)
        close(pipe_out[PIPE_READ_ENDPOINT]);
    if (pipe_out[PIPE_WRITE_ENDPOINT] != -1)
        close(pipe_out[PIPE_WRITE_ENDPOINT]);
    if (pipe_err[PIPE_READ_ENDPOINT] != -1)
        close(pipe_err[PIPE_READ_ENDPOINT]);
    if (pipe_err[PIPE_WRITE_ENDPOINT] != -1)
        close(pipe_err[PIPE_WRITE_ENDPOINT]);
}

static void pipes_close_unneeded(int pipe_in[], int pipe_out[], int pipe_err[])
{
    if (pipe_in[PIPE_READ_ENDPOINT] != -1)
        close(pipe_in[PIPE_READ_ENDPOINT]);
    if (pipe_out[PIPE_WRITE_ENDPOINT] != -1)
        close(pipe_out[PIPE_WRITE_ENDPOINT]);
    if (pipe_err[PIPE_WRITE_ENDPOINT] != -1)
        close(pipe_err[PIPE_WRITE_ENDPOINT]);
}

static int pipes_open(int *fd_in, int *fd_out, int *fd_err, int pipe_in[],
    int pipe_out[], int pipe_err[])
{
    if (fd_in)
    {
        if (pipe(pipe_in) == -1)
        {
            log_message(LERR, "Failed to create in pipe, error: %s\n",
                strerror(errno));
            goto Error;
        }
        *fd_in = pipe_in[PIPE_WRITE_ENDPOINT];
    }

    if (fd_out)
    {
        if (pipe(pipe_out) == -1)
        {
            log_message(LERR, "Failed to create out pipe, error: %s\n",
                strerror(errno));
            goto Error;
        }
        *fd_out = pipe_out[PIPE_READ_ENDPOINT];
    }

    if (fd_err)
    {
        if (pipe(pipe_err) == -1)
        {
            log_message(LERR, "Failed to create err pipe, error: %s\n",
                strerror(errno));
            goto Error;
        }
        *fd_err = pipe_err[PIPE_READ_ENDPOINT];
    }

    return 0;

Error:
    pipes_close(pipe_in, pipe_out, pipe_err);
    return -1;
}

static int pipes_connect(int pipe_in[], int pipe_out[], int pipe_err[])
{
    int ret = -1;

    if (pipe_in[PIPE_READ_ENDPOINT] != -1)
    {
        if (dup2(pipe_in[PIPE_READ_ENDPOINT], STDIN_FILENO) == -1)
        {
            log_message(LERR, "Failed to duplicate stdin file descriptor,"
                " error: %s\n", strerror(errno));
            goto Exit;
        }
    }

    if (pipe_out[PIPE_WRITE_ENDPOINT] != -1)
    {
        if (dup2(pipe_out[PIPE_WRITE_ENDPOINT], STDOUT_FILENO) == -1)
        {
            log_message(LERR, "Failed to duplicate stdout file descriptor,"
                " error: %s\n", strerror(errno));
            goto Exit;
        }
    }

    if (pipe_err[PIPE_WRITE_ENDPOINT] != -1)
    {
        if (dup2(pipe_err[PIPE_WRITE_ENDPOINT], STDERR_FILENO) == -1)
        {
            log_message(LERR, "Failed to duplicate stderr file descriptor,"
                " error: %s\n", strerror(errno));
            goto Exit;
        }
    }

    ret = 0;
Exit:
    pipes_close(pipe_in, pipe_out, pipe_err);
    return ret;
}

int process_execute(char *path, char *const argv[], pid_t *pid, int *pfd_in,
    int *pfd_out, int *pfd_err)
{
    int pipe_in[2] = { -1, -1 }, pipe_out[2] = { -1, -1 },
        pipe_err[2] = { -1, -1 };

    if (pipes_open(pfd_in, pfd_out, pfd_err, pipe_in, pipe_out, pipe_err)
        == -1)
    {
        return -1;
    }

    *pid = fork();
    if (*pid == -1)
    {
        pipes_close(pipe_in, pipe_out, pipe_err);
        log_message(LERR, "Failed to fork the process, error: %s\n",
            strerror(errno));
        return -1;
    }
    else if (*pid == 0)
    {
        if (pipes_connect(pipe_in, pipe_out, pipe_err) == -1)
        {
            return -1;
        }

        if (execv(path, argv) == -1)
        {
            log_message(LERR, "Failed to execute %s, error: %s\n",
                path, strerror(errno));
            return -1;
        }
    }
    else
    {
        pipes_close_unneeded(pipe_in, pipe_out, pipe_err);     
    }

    return 0;
}

int process_terminate(pid_t pid)
{
    int wstatus;

    if (pid <= 0)
    {
        return 0;
    }

    if (kill(pid, SIGTERM) == -1)
    {
        log_message(LERR, "Failed to kill %d process, "
            "error: %s\n", pid, strerror(errno));
        return -1;
    }

    if (waitpid(pid, &wstatus, 0) == -1)
    {
        log_message(LERR, "Failed to wait %d process termination, "
            "error: %s\n", pid, strerror(errno));
        return -1;
    }

    return 0;
}
