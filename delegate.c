#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "syscalls.h"
#include "log.h"
#define NAME "socket"
#define handle_error(msg) do {perror(msg); exit(EXIT_FAILURE);} while (0)

extern char policy_name[150];

void *handle_connection(void *sock) {
  int msgsock = *(int *)sock;
  int rval;
  char buf[1024];
  if (msgsock == -1)
    perror("accept");
  else
    do {
      bzero(buf, sizeof(buf));
      if ((rval = read(msgsock, buf, 1024)) < 0) {
        printf("fd: %d\n", msgsock);
        perror("reading stream message");
      }

      else if (rval == 0)
        break;

      else {
        char *ptr = strchr(buf, ',');
        int syscall_num = atoi(buf);
        switch (syscall_num) {
        case __NR_rmdir:
          rmdir_(ptr + 1, msgsock);
          break;
        case __NR_unlinkat:
          unlinkat_(ptr + 1, msgsock);
          break;
        case __NR_unlink:
          unlink_(ptr + 1, msgsock);
          break;
        case __NR_chmod:
          chmod_(ptr + 1, msgsock);
          break;
        case __NR_truncate:
          truncate_(ptr + 1, msgsock);
          break;
        case __NR_rename:
          rename_(ptr + 1, msgsock);
          break;
        case __NR_creat:
          creat_(ptr + 1, msgsock);
          break;
        case __NR_mkdir:
          make_dir(ptr + 1, msgsock);
          break;
        case __NR_openat:
          open_at(ptr + 1, msgsock);
          break;
        case __NR_open:
          open_(ptr + 1, msgsock);
          break;
        case 786:
          fopen_(ptr + 1, msgsock);
          break;
        case 787:
          open64_(ptr + 1, msgsock);
          break;
        case 780:
          opendir_(ptr + 1, msgsock);
          break;
        case 790:
          openat64_(ptr + 1, msgsock);
          break;
        case 791:
          fchmodat_(ptr+1,msgsock);
          break;
        default:
          break;
        }
      }
    } while (rval > 0);
  close(msgsock);
}

int main() {
  FILE* fp;
  strcpy(policy_name, getenv("SAFEX_POLICY"));
  int sock, msgsock, rval;
  char buf[1024];
  struct sockaddr_in serv_addr, cli_addr;

  fp = fopen("delegate.log", "w+");
  log_add_fp(fp, LOG_INFO);
  log_set_quiet(true);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("opening stream socket");
    exit(1);
  }
  int portno = 5001;

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  serv_addr.sin_port = htons(portno);
  int bind_val = bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if (bind_val) {
    printf("bind error: %d\n", bind_val);
    perror("binding stream socket");
    exit(1);
  }
  int enable = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    perror("setsockopt(SO_REUSEADDR) failed");
  listen(sock, 5);
  socklen_t clilen = sizeof(cli_addr);
  for (;;) {
    pthread_t tid;
    msgsock = accept(sock, (struct sockaddr *)&cli_addr, &clilen);
    pthread_create(&tid, NULL, handle_connection, (void *)&msgsock);
  }
  close(sock);
  unlink(NAME);
  fclose(fp);
  return 0;
}
