/*
 * Copyright (C) 2020 Webistics Holdings Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
#ifndef ANDROID_EXE_H
#define ANDROID_EXE_H

#define CRED_BUF_LEN 100

typedef struct server_command {
    char command[CRED_BUF_LEN];
    char param1[CRED_BUF_LEN];
    char param2[CRED_BUF_LEN];
    int fd;
} server_command;

int send_command(int socket_fd, char* cmd);
int send_command_with_fd(int socket_fd, char* cmd, int fd);

#endif
