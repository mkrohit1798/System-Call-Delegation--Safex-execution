#include <stdio.h>
#include <unistd.h>

int main ()
{
    if(rmdir("abc") == -1) 
        printf("Error\n");
    else
        printf("Success\n");

    return 0;
}