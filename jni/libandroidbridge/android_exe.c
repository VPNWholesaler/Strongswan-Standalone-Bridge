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
#define  _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include  <stdio.h>//for printf
#include  <stdlib.h>//for exit
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <android/log.h>
#include "charonservice.h"
#include <unistd.h>
#include <pthread.h>
#include "android_exe.h"
#include "vpnservice_builder.h"

bool __isspace (unsigned char c)
{
  if ( c == ' '
    || c == '\f'
    || c == '\n'
    || c == '\r'
    || c == '\t'
    || c == '\v' )
      return TRUE;

  return FALSE;
}


#define NEED_PASSWORD ">PASSWORD:Need 'Auth' username/password\n"

#define ERR(msg...) __android_log_print(ANDROID_LOG_VERBOSE, "charon", msg)


char *strstrip(char *s)
{
        size_t size;
        char *end;

        size = strlen(s);

        if (!size)
                return s;

        end = s + size - 1;
        while (end >= s && __isspace(*end))
                end--;
        *(end + 1) = '\0';

        while (*s && __isspace(*s))
                s++;

        return s;
}

int wait_response(int socket_fd, server_command* cmd) {
    ERR("Waiting for server response\n");
    char buf[CRED_BUF_LEN * 3 + 3];
    memset(&buf, 0, sizeof(buf));
    memset(cmd, 0, sizeof(*cmd));
    struct msghdr msghdr;
    struct iovec iov[1];
    union {
            struct cmsghdr cm;
            char control[CMSG_SPACE(sizeof(int))];
        } control_un;
    struct cmsghdr  *cmptr;

    msghdr.msg_control  = control_un.control;
    msghdr.msg_controllen = sizeof(control_un.control);

    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    //int n = recv(socket_fd, buf, sizeof(buf), 0);
    int n = recvmsg(socket_fd, &msghdr, MSG_NOSIGNAL);
    if (n <= 0) {
        ERR("Nothing received\n");
        return -1;
    }
     cmd->fd = -1;
    if ( (cmptr = CMSG_FIRSTHDR(&msghdr)) != NULL && cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        cmd->fd = *((int *) CMSG_DATA(cmptr));
    }
    char * pch = strtok (buf," ");
    if (pch != NULL) {
        strcpy(cmd->command, strstrip(pch));
        pch = strtok(NULL, " ");
        if (pch != NULL) {
            strcpy(cmd->param1, strstrip(pch));
            pch = strtok(NULL, " ");
            if (pch != NULL) {
                strcpy(cmd->param2, strstrip(pch));
            }
        }
    }
    return 0;

}

typedef struct charon_start_data {
  char* remote;
  char* username;
  char* password;
  char* logfile;
  vpnservice_builder_t * builder;
} charon_start_data;

void *start_charon(void *start_data) {

    charon_start_data *data = (charon_start_data*)start_data;

    initializeCharon(data->logfile, data->builder, FALSE);

    printf("Ready to start\n");
    initiateCharon("ikev2-eap", data->remote, data->username, data->password);
}


int send_command(int socket_fd, char* cmd) {

  if (send(socket_fd, cmd, strlen(cmd) , 0) == -1) {
      close(socket_fd);
      ERR("Error in send\n");
      return -1;
  }
  return 0;
}

int send_command_with_fd(int socket_fd, char* cmd, int fd) {
    struct msghdr msg;
    struct iovec iov[1];

    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    cmptr = CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len = CMSG_LEN(sizeof(int));
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    *((int *) CMSG_DATA(cmptr)) = fd;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    iov[0].iov_base = cmd;
    iov[0].iov_len = strlen(cmd);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if (sendmsg(socket_fd, &msg, MSG_NOSIGNAL) == -1) {
        return -1;
    }
    return 0;

}

int run(char* remote, char* socket_path, char* logfile) {
  ERR("Trying to connect to socket\n");
  int socket_fd;
  struct sockaddr_un server_address;
  if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
  {
      ERR("server: socket error\n");
      return -1;
  }
  memset(&server_address, 0, sizeof(server_address));
  server_address.sun_family = AF_UNIX;
  strcpy(server_address.sun_path, socket_path);
  socklen_t address_length = sizeof(server_address);

  if (connect(socket_fd, (struct sockaddr *)&server_address, address_length) == -1) {
    ERR("Error connecting to server\n");
    close(socket_fd);
    return -1;
  }

  ERR("Connection successful\n");
  send_command(socket_fd, NEED_PASSWORD);

  char username[BUF_LEN];
  char password[BUF_LEN];

  memset(username, 0, sizeof(username));
  memset(password, 0, sizeof(password));

  server_command next_command;

  pthread_cond_t  condition_cond  = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
  vpnservice_builder_t *builder = vpnservice_builder_create(socket_fd, &condition_cond, &lock);

  for (;;) {
      ERR("Waiting for server response\n");
      wait_response(socket_fd, &next_command);
      ERR("Received command %s", next_command.command);
      if (strcmp(next_command.command, "signal") == 0 && strcmp(next_command.param1, "SIGINT") == 0) {
          ERR("Received SIGINT. Terminating...\n");
          break;
      }
      if (strcmp(next_command.command, "username") == 0) {
          strcpy(username, next_command.param2);
      } else if (strcmp(next_command.command, "password") == 0) {
          strcpy(password, next_command.param2);
          ERR("Ready to establish connection with %s using %s %s\n", remote, username, password);
          charon_start_data data;
          data.remote = remote;
          data.password = password;
          data.username = username;
          data.logfile = logfile;
          data.builder = builder;
          pthread_t thread_id;
          //start_charon(remote, username, password, logfile, builder);
          pthread_create(&thread_id, NULL, start_charon, &data);
      } else if (strcmp(next_command.command, "needok") == 0) {
           pthread_mutex_lock(&lock);
           builder->set_needok_result(builder, next_command.param1, next_command.fd);
           //pthread_cond_signal(&condition_cond);
           pthread_mutex_unlock(&lock);
      }

  }

  close(socket_fd);

  return 0;

}

int main(int argc, char **argv)
{
  if (argc != 3) {
      printf("Usage android_exe --config /path/to/config/file\n");
      return 0;
      exit(0);
  } else {
        char * remote = NULL;
        char * socket_path = NULL;
        char * log_file = NULL;
        FILE * fp;
        char line[255];

        fp = fopen(argv[2], "r");
        if (fp == NULL)
            exit(EXIT_FAILURE);

        while (fgets(line, 255, fp) != NULL) {
            char * pch;
            pch = strtok (line," ");
            if (strcmp(pch, "remote") == 0) {
                char * pch2 = strtok(NULL, " ");
                remote = malloc(strlen(pch2));
                strcpy(remote, pch2);
            }
            if (strcmp(pch, "management") == 0) {
                char * pch2 = strtok(NULL, " ");
                socket_path = malloc(strlen(pch2));
                strcpy(socket_path, pch2);
            }
            if (strcmp(pch, "log-append") == 0) {
                char * pch2 = strtok(NULL, " ");
                log_file = malloc(strlen(pch2));
                strcpy(log_file, pch2);
            }
        }

        fclose(fp);
        int params = 0;

        if (remote) {
            ERR("Remote: %s\n", remote);
            params++;
        }
        if (socket_path) {
            ERR("Path to socket: %s\n", socket_path);
            params++;
        }
        if (log_file) {
            ERR("Path to log: %s\n", log_file);
            params++;
        }
        int result = -1;
        if (params == 3) {
            result = run(remote, socket_path, log_file);
        } else {
            ERR("Configuration is invalid\n");
        }
        if (remote) {
            free(remote);
        }
        if (socket_path) {
            free(socket_path);
        }
        return result;
        exit(result);
  }
}
