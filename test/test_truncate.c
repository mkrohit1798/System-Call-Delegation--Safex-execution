#include<stdio.h>
#include<unistd.h>

int main()
{
	int ret;
	ret = truncate("test.txt", 40);
	if(ret == -1)
	{
		printf("failed\n");
		return -1;
	} else {
        printf("Success\n");
    }
	return 0;
}