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

#define NAME "socket"

#ifdef ENABLE_DEBUG
FILE *fp;
#endif

// setting up seccomp filters //
__attribute__((constructor)) void configure_seccomp(void) {
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      //BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mkdir, 13, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlinkat, 12, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlink, 11, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chmod, 10, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_truncate, 9, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rename, 8, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_creat, 7, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rmdir, 6, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 3),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, args[2]))),
      BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 2 | 64 | 1),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 2),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };
  // struct sock_filter filter[] = {
  //     BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
  //     //BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mkdir, 13, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlinkat, 12, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlink, 11, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chmod, 10, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_truncate, 9, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rename, 8, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_creat, 7, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rmdir, 6, 0),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 5, 0),
  //     BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
  //     BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
  //     BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
  //     BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
  //     BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 0, 1),
  //     BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
  //     BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  // };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
  }

  if (prctl(PR_SET_SECCOMP, 2, &prog)) {
    perror("prctl(PR_SET_SECCOMP)");
  }
// file for logging //
#ifdef ENABLE_DEBUG
  fp = fopen("syscall.log", "w+");
  log_add_fp(fp, LOG_INFO);
  log_set_quiet(true);
#endif
}

__attribute__((destructor)) void finish() {
#ifdef ENABLE_DEBUG
  fclose(fp);
#endif
}
