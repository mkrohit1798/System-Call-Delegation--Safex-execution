#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

int main()
{   char mode[] = "0777";
    char buf[100] = "abc";
    int i;
    i = strtol(mode, 0, 8);
    if (chmod (buf ,i) < 0)
    {
        printf("error\n");
        exit(1);
    }
    else{
        printf("Success\n");
    }
    return(0);
}