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
#include "socketcalls.h"


int recv_fd(int msg_socket) {
    int file_d = -1;
    char message[130];
    read(msg_socket,&message,sizeof(message));
    char *ptr = strchr(message,',');
    file_d = atoi(message);
    if(file_d>0){
        char *unix_socket = strtok(ptr+1,",");
        struct sockaddr_un server;
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("opening stream socket");
            exit(1);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, unix_socket);

        int connect_val = 0;
        while (1)
        {
            connect_val = connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
            if (connect_val >= 0) {
                break;
            }
        }

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

        if (recvmsg (sock, &msg, 0) < 0)
                handle_error ("Failed to receive message");

        cmsg = CMSG_FIRSTHDR(&msg);

        memcpy (fd, (int *) CMSG_DATA(cmsg),sizeof(int));
        return *fd;
    }
    return file_d;
}


void send_fd(int msg_socket, int fd)
{
        char unix_socket[120];
        read(msg_socket, &unix_socket,sizeof(unix_socket));
        struct sockaddr_un server;
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("opening stream socket");
            exit(1);
        }
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, unix_socket);

        int connect_val = 0;
        while (1)
        {
            connect_val = connect(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
            if (connect_val >= 0) {
                break;
            }
        }

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
        if (sendmsg (sock, &msg, 0) < 0)
                handle_error ("Failed to send message");
        fflush(stdout);
}

int make_connection(){
   struct sockaddr_in serv_addr;
   int portno = 5001;
   inet_pton(AF_INET, "127.0.0.1",&serv_addr.sin_addr.s_addr);
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
    return sock;
}

int creat (const char *path, mode_t mode) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d,%s,%d",__NR_creat, path, mode);
    #ifdef ENABLE_DEBUG
    log_info("creat system call called with path \"%s\" and mode - %d", path,
           mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("creat system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);

}

int rename (const char *oldpath, const char *newpath) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d,%s,%s",__NR_rename, oldpath, newpath);
    #ifdef ENABLE_DEBUG
    log_info("rename system call called with old path \"%s\" and newpath \"%s\"",
        oldpath, newpath);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    read(sock, &return_val,sizeof(return_val));
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("rename system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);

}

int truncate (const char *path, off_t length) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d,%s,%ld",__NR_truncate, path, length);
    #ifdef ENABLE_DEBUG
    log_info("truncate system call called with path \"%s\" and length - %d", path,
           length);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    read(sock, &return_val,sizeof(return_val));
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("truncate system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);

}

 int chmod (const char *pathname, mode_t mode) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d,%s,%d",__NR_chmod, pathname, mode);
    #ifdef ENABLE_DEBUG
    log_info("chmod system call called with path \"%s\" and mode - %d", pathname,
           mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    read(sock, &return_val,sizeof(return_val));
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("chmod system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);
}

 int fchmodat (int dirfd, const char *pathname, mode_t mode, int flags) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d,%d,%s,%d,%d",791, dirfd,pathname, mode,flags);
    #ifdef ENABLE_DEBUG
    log_info("chmod system call called with path \"%s\" and mode - %d", pathname,
           mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");
    if(dirfd>0){
        send_fd(sock,dirfd);
    }
    read(sock, &return_val,sizeof(return_val));
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("chmod system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);
}


// int mkdir (const char *pathname, mode_t mode){
//     int sock;
//     u_int32_t return_val;
//     char message[1056];
//     sprintf(message,"%d,%s,%d",__NR_mkdir, pathname, mode);
//     log_info("mkdir system call called with path \"%s\" and mode - %d", pathname, mode);
//     sock = make_connection();
//     if (write(sock, message, strlen(message)) < 0)
//         perror("writing on stream socket");

//     read(sock, &return_val,sizeof(return_val));
//     close(sock);
//     log_info("mkdir system call returned with value - %d", ntohl(return_val));
// 	return ntohl(return_val);
// }

int unlink (const char *pathname) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d, %s" ,__NR_unlink, pathname);
    #ifdef ENABLE_DEBUG
    log_info("unlink system call called with path \"%s\"", pathname);
    #endif

    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    read(sock, &return_val,sizeof(return_val));
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("unlink system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);

}

int unlinkat(int dirfd, const char *pathname, int flags) {
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%d,%s,%d", __NR_unlinkat, dirfd, pathname, flags);
    #ifdef ENABLE_DEBUG
    log_info("unlink at system call called with path \"%s\", flags - %d", pathname, flags);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    if(dirfd>0){
        send_fd(sock,dirfd);
    }
    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("unlinkat system call returned with value - %d", return_val);
    #endif
	return return_val;
}

int rmdir (const char *pathname) {
    int sock;
    u_int32_t return_val;
    char message[1056];
    sprintf(message,"%d, %s" , __NR_rmdir, pathname);
    #ifdef ENABLE_DEBUG
    log_info("rmdir system call called with path \"%s\"", pathname);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    read(sock, &return_val,sizeof(return_val));
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("rmdir system call returned with value - %d", ntohl(return_val));
    #endif
	return ntohl(return_val);

}

int open(const char *pathname, int flags, mode_t mode){
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%s,%d,%d",__NR_open,pathname,flags,mode);
    #ifdef ENABLE_DEBUG
    log_info("open system call called with path \"%s\", flags - %d and mode - %d", pathname, flags, mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("open system call returned with value - %d", return_val);
    #endif
	return return_val;
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode){
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%d,%s,%d,%d",__NR_openat,dirfd,pathname,flags,mode);
    #ifdef ENABLE_DEBUG
    log_info("openat system call called with path \"%s\", flags - %d and mode - %d", pathname, flags, mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    if(dirfd>0){
        send_fd(sock,dirfd);
    }
    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("openat system call returned with value - %d", return_val);
    #endif
	return return_val;
}

int openat64(int dirfd, const char *pathname, int flags, mode_t mode){
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%d,%s,%d,%d",790,dirfd,pathname,flags,mode);
    #ifdef ENABLE_DEBUG
    log_info("openat64 system call called with path \"%s\", dirfd - %d, flags - %d and mode - %d" ,pathname, dirfd, flags, mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    if(dirfd>0){
        send_fd(sock,dirfd);
    }
    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("openat64 system call returned with value - %d", return_val);
    #endif
	return return_val;
}



FILE *fopen(const char *restrict pathname, const char *restrict mode){
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%s,%s",786,pathname,mode);
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    return_val = recv_fd(sock);
    close(sock);
    FILE *file = fdopen(return_val,mode);
	return file;
}

int open64(const char *pathname, int flags, mode_t mode){
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%s,%d,%d",787,pathname,flags,mode);
    #ifdef ENABLE_DEBUG
    log_info("open64 system call called with path \"%s\", flags - %d and mode - %d", pathname, flags, mode);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("open64 system call returned with value - %d", return_val);
    #endif
	return return_val;
}

DIR *opendir(const char *name){
    int sock;
    u_int32_t return_val;

    char message[1056];

    sprintf(message,"%d,%s",780,name);
    #ifdef ENABLE_DEBUG
    log_info("opendir system call called with name \"%s\"", name);
    #endif
    sock = make_connection();
    if (write(sock, message, strlen(message)) < 0)
        perror("writing on stream socket");

    return_val = recv_fd(sock);
    close(sock);
    #ifdef ENABLE_DEBUG
    log_info("opendir system call returned with value - %d", return_val);
    #endif
    DIR *dir=fdopendir(return_val);
	return dir;
}