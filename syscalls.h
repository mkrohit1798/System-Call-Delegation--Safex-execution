#ifndef SYSCALLS_H
#define SYSCALLS_H
#include <stdio.h>

int recv_fd(int msg_socket);
void send_fd(int msg_socket, int fd);
void creat_(char *buf, int msgsock);
void rename_(char *buf, int msgsock);
void truncate_(char *buf, int msgsock);
void chmod_(char *buf, int msgsock);
void make_dir(char *buf, int msgsock);
void unlink_(char *buf, int msgsock);
void unlinkat_(char *buf, int msgsock);
void rmdir_(char *buf, int msgsock);
void open_at(char *buf, int msgsock);
void openat64_(char *buf, int msgsock);
void open64_(char *buf, int msgsock);
void open_(char *buf, int msgsock);
void fopen_(char *buf, int msgsock);
void opendir_(char *buf, int msgsock);
void fchmodat_(char *buf, int msgsock);
#endif