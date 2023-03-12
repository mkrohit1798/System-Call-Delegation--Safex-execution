#include <stdio.h>
#include <fcntl.h>
#define PERMS 0666 

const char* filename = "creat_text";
int main () {
    int fd;

    if ( (fd = creat(filename, PERMS)) == -1 )
        printf("error\n");
    else
        printf("success\n");
    return 0;
}