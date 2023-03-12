#ifndef SOCKETCALLS_H
#define SOCKETCALLS_H

#include <asm/unistd_64.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/types.h>
#include <dirent.h>

#include "log.h"
#define handle_error(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)

int creat (const char *path, mode_t mode);
int rename (const char *oldpath, const char *newpath);
int truncate (const char *path, off_t length);
int chmod (const char *pathname, mode_t mode);
int mkdir (const char *pathname, mode_t mode);
int unlink (const char *pathname);
int rmdir (const char *pathname);
int open(const char *pathname, int flags, mode_t mode);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
int openat64(int dirfd, const char *pathname, int flags, mode_t mode);
FILE *fopen(const char *restrict pathname, const char *restrict mode);
int open64(const char *pathname, int flags, mode_t mode);
DIR *opendir(const char *name);
int recv_fd(int msg_socket);
void send_fd(int msg_socket, int fd);
int make_connection();

#endif