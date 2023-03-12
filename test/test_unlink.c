#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main ()
{
    if(unlink("abc") == -1) {
       // perror("");
        exit(-1);
    }
    else
        printf("Success\n");

    return 0;
}