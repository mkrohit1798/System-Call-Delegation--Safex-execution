#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>

void run(char **arglist, char **envlist, char *policy_name) {
    int delegate = fork();
    if(delegate == 0) {
        char policy[100];
        sprintf(policy, "SAFEX_POLICY=%s", policy_name);
        char *delegate_envlist[] = {policy, NULL};
        char delegate_executable[100] = "./delegate";
        char *delegate_arglist[] = {delegate_executable, NULL};
        execvpe(delegate_executable, delegate_arglist, delegate_envlist);
    }
    else {
        int untrusted = fork();
        if(untrusted == 0) {
            execvpe(arglist[0], arglist, envlist);
        }
        else {            
            waitpid(untrusted, NULL, 0);
            kill(delegate, SIGTERM);
        }
    }

}

int main(int argc, char* argv[], char **envp) {
    // check the input format //
    if(argc < 4 || (strcmp(argv[1],"--policy")!=0)){
        printf("Error\nUsage: ./safex --policy <policy_name> <command_to_execute>\n");
        exit(1);
    }
    if( access(argv[2], F_OK ) != 0 ) {
        printf("Error: The specified policy file does not exist\n");
        exit(1);
    }

    int env_count = 0;
    int i = 0;
    for (i = 0; envp[i]; i++) {
        env_count++;
    }
    char **envlist = (char **)malloc((env_count + 2) * sizeof(void *));
    for (i = 0; i < env_count; i++) {
        envlist[i] = envp[i];
    }
    // adding LD_PRELOAD to the envlist //
    char cwd[100];
    getcwd(cwd, sizeof(cwd));
    char ld_preload[125];
    sprintf(ld_preload, "LD_PRELOAD=%s/libsafex.so", cwd);
    envlist[i++] = ld_preload;
    envlist[i] = NULL;
    // rearranging the arglist from argv //
    char **arglist = (char **) malloc(argc * sizeof(void *));
    for(i = 3; i < argc; i++){
        arglist[i-3] = argv[i];
    }
    arglist[i] = NULL;
    // fork and run the delegate and the untrusted process //
    run(arglist, envlist, argv[2]);

    return 0;
}
