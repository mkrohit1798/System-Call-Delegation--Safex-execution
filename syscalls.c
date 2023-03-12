#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "log.h"
#include "syscalls.h"
#define handle_error(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)

char policy_name[150];

int policy_check(const char* pathname,int flags){
    struct sockaddr_in serv_addr;
    int portno = 8081;
    inet_pton(AF_INET, "127.0.0.1",&serv_addr.sin_addr.s_addr);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("opening stream socket");
        exit(1);
    }

    int connect_val = 0;
    connect_val = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (connect_val < 0) {
        close(sock);
        fflush(stdout);
        perror("connecting stream socket");
        exit(1);
    }
    char message[1056];
    char cwd[100];
    getcwd(cwd,sizeof(cwd));
    sprintf(message,"GET /check HTTP/1.0\r\n"
    "Policy: %s\r\n"
    "Path: %s\r\n"
    "Flags: %d\r\n"
    "Mode: %s\r\n"
    "Cwd: %s\r\n"
    "Host: localhost:8081\r\n"
    "Connection: close\r\n\r\n",policy_name,pathname,flags,"",cwd);
    write(sock, message, strlen(message));
    read(sock,&message,strlen(message));
    if(message[9] == '2')
        return 1;
    else
        return 0;
}

int recv_fd(int msg_socket) {
        int *fd = malloc (sizeof(int));
        struct msghdr msg = {0};
        struct cmsghdr *cmsg;
        char buf[CMSG_SPACE(sizeof(int))], dup[256];
        memset(buf, '\0', sizeof(buf));
        struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);
        char cwd[100];
        getcwd(cwd,sizeof(cwd));
        char unix_socket[120];
        sprintf(unix_socket,"%s/socket-%d",cwd,rand());
        char message[130];
        write(msg_socket,&unix_socket,sizeof(unix_socket));
        struct sockaddr_un server;
        int sock,msgsock;

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket < 0) {
            perror("opening stream socket");
            exit(1);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, unix_socket);
        if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
            perror("binding stream socket");
            exit(1);
        }
        listen(sock, 5);
        msgsock = accept(sock, 0, 0);

        if (recvmsg (msgsock, &msg, 0) < 0)
                handle_error ("Failed to receive message");

        cmsg = CMSG_FIRSTHDR(&msg);

        memcpy (fd, (int *) CMSG_DATA(cmsg),sizeof(int));
        char command[130];
        sprintf(command,"rm -rf %s",unix_socket);
        system(command);
        return *fd;
}

void send_fd(int msg_socket, int fd)
{
    char cwd[100];
    getcwd(cwd,sizeof(cwd));
    char unix_socket[120];
    sprintf(unix_socket,"%s/socket-%d",cwd,rand());
    char message[130];
    sprintf(message,"%d,%s",fd,unix_socket);
    write(msg_socket,&message,sizeof(message));
    if(fd>0){
        struct sockaddr_un server;
        int sock,msgsock;

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket < 0) {
            perror("opening stream socket");
            exit(1);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, unix_socket);
        if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
            perror("binding stream socket");
            exit(1);
        }
        listen(sock, 5);
        msgsock = accept(sock, 0, 0);
        int ack;
        struct msghdr msg = {0};
        struct cmsghdr *cmsg;
        char buf[CMSG_SPACE(sizeof(int))], dup[256];
        memset(buf, '\0', sizeof(buf));
        struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = buf;
        msg.msg_controllen = sizeof(buf);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        memcpy ((int *) CMSG_DATA(cmsg), &fd, sizeof (int));
        if (sendmsg (msgsock, &msg, 0) < 0)
                handle_error ("Failed to send message");
        close(fd);
        char command[130];
        sprintf(command,"rm -rf %s",unix_socket);
        system(command);
    }
}

void creat_(char *buf, int msgsock){
    char* pathname = strtok(buf, ",");
    char* mode_s = strtok(NULL,",");
    int fd = -1;
    if(policy_check(pathname,1)==0){
        send_fd(msgsock,fd);
        return;
    }
    fd = creat(pathname, atoi(mode_s));
    fflush(stdout);
    #ifdef ENABLE_DEBUG
    log_info("creat requested with %s ",buf);
    #endif
    send_fd(msgsock,fd);
}

void rename_(char *buf, int msgsock){
    char* oldpath = strtok(buf, ",");
    char* newpath = strtok(NULL,",");
    int return_val = -1;
    if(policy_check(oldpath,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    return_val = rename(oldpath, newpath);
    #ifdef ENABLE_DEBUG
    log_info("rename requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock, &return_val, sizeof(return_val));
}

void truncate_(char *buf, int msgsock){
    char* path = strtok(buf, ",");
    char* size = strtok(NULL,",");
    int return_val = -1;
    if(policy_check(path,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    return_val = truncate(path, atoi(size));
    #ifdef ENABLE_DEBUG
    log_info("truncate requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock, &return_val, sizeof(return_val));
}

void chmod_(char *buf, int msgsock){
    char* path = strtok(buf, ",");
    char* mode_s = strtok(NULL,",");
    int return_val = -1;
    if(policy_check(path,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    return_val = chmod(path, atoi(mode_s));
    #ifdef ENABLE_DEBUG
    log_info("chmod requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock, &return_val, sizeof(return_val));
}

void fchmodat_(char *buf, int msgsock){
    char* token = strtok(buf, ",");
    int dirfd = atoi(token);
    char* path = strtok(NULL, ",");
    char* mode_s = strtok(NULL,",");
    char* flags = strtok(NULL,",");
    int return_val = -1;
    if(policy_check(path,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    if(dirfd > 0){
        char dirpath[1000];
        dirfd=recv_fd(msgsock);
    }
    return_val = fchmodat(dirfd, path, atoi(mode_s),atoi(flags));
    #ifdef ENABLE_DEBUG
    log_info("chmod requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock, &return_val, sizeof(return_val));
}

void make_dir(char *buf, int msgsock){
    char* pathname = strtok(buf, ",");
    char* mode_s = strtok(NULL,",");
    int return_val= -1;
    if(policy_check(pathname,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    return_val = mkdir(buf,atoi(mode_s));
    #ifdef ENABLE_DEBUG
    log_info("mkdir requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock,&return_val,sizeof(return_val));
}

void unlink_(char *buf, int msgsock){
    char* pathname = ++buf;
    int return_val = -1;
    if(policy_check(pathname,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    return_val = unlink(pathname);
    #ifdef ENABLE_DEBUG
    log_info("unlink requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock, &return_val, sizeof(return_val));
}

void unlinkat_(char *buf, int msgsock){
    char *token = strtok(buf,",");
    int dirfd = atoi(token);
    const char *pathname = strtok(NULL,",");
    token = strtok(NULL,",");
    int flags = atoi(token);
    if(dirfd > 0){
        char dirpath[1000];
        dirfd=recv_fd(msgsock);
    }
    int fd = unlinkat(dirfd,pathname,flags);
    fflush(stdout);
    log_info("unlinkat requested with %s ",buf);
    send_fd(msgsock,fd);
}

void rmdir_(char *buf, int msgsock){
    char* pathname = ++buf;
    int return_val = -1;
    if(policy_check(pathname,1)==0){
        write(msgsock, &return_val, sizeof(return_val));
        return;
    }
    return_val = rmdir(pathname);
    #ifdef ENABLE_DEBUG
    log_info("rmdir requested with %s returned with - %d",buf, ntohl(return_val));
    #endif
    write(msgsock, &return_val, sizeof(return_val));
}

void open_at(char *buf, int msgsock){
    char *token = strtok(buf,",");
    int dirfd = atoi(token);
    const char *pathname = strtok(NULL,",");
    token = strtok(NULL,",");
    int flags = atoi(token);
    if(policy_check(pathname,flags)==0){
        send_fd(msgsock,-1);
        return;
    }
    if(dirfd > 0){
        char dirpath[1000];
        dirfd=recv_fd(msgsock);
    }
    int fd = openat(dirfd,pathname,flags);
    fflush(stdout);
    log_info("openat requested with %s ",buf);
    send_fd(msgsock,fd);
}

void openat64_(char *buf, int msgsock){
    char *token = strtok(buf,",");
    int dirfd = atoi(token);
    const char *pathname = strtok(NULL,",");
    token = strtok(NULL,",");
    int flags = atoi(token);
    if(policy_check(pathname,flags)==0){
        send_fd(msgsock,-1);
        return;
    }
    if(dirfd > 0){
        dirfd=recv_fd(msgsock);
    }
    int fd = openat64(dirfd,pathname,flags);
    fflush(stdout);
    #ifdef ENABLE_DEBUG
    log_info("openat64 requested with %s ",buf);
    #endif
    send_fd(msgsock,fd);
}

void open64_(char *buf, int msgsock){
    const char *pathname = strtok(buf,",");
    char *token = strtok(NULL,",");
    int flags = atoi(token);
    token = strtok(NULL,",");
    if(policy_check(pathname,flags)==0){
        send_fd(msgsock,-1);
        return;
    }
    mode_t mode = atoi(token);
    int fd = open64(pathname,flags,mode);
    #ifdef ENABLE_DEBUG
    log_info("open64 requested with %s ",buf);
    #endif
    send_fd(msgsock,fd);
}

void open_(char *buf, int msgsock){
    const char *pathname = strtok(buf,",");
    char *token = strtok(NULL,",");
    int flags = atoi(token);
    token = strtok(NULL,",");
    if(policy_check(pathname,flags)==0){
        send_fd(msgsock,-1);
        return;
    }
    mode_t mode = atoi(token);
    int fd = open(pathname,flags,mode);
    #ifdef ENABLE_DEBUG
    log_info("open requested with %s ",buf);
    #endif
    send_fd(msgsock,fd);
}

void fopen_(char *buf, int msgsock){
    const char *pathname = strtok(buf,",");
    char *mode = strtok(NULL,",");
    FILE* file = fopen(pathname,mode);
    int fd=-1;
    if(file != NULL){
        fd = fileno(file);
    }
    send_fd(msgsock,fd);
}

void opendir_(char *buf, int msgsock){
    fflush(stdout);
    DIR* dir = opendir(buf);
    int fd=-1;
    if(dir!=NULL){
        fd = dirfd(dir);
    }
    #ifdef ENABLE_DEBUG
    log_info("opendir requested with %s ",buf);
    #endif
    send_fd(msgsock,fd);
}