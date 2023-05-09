#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void hello_world() {
    printf("hello, world!\n");
}

int main(int argc, char *argv[])
{
    struct timespec req;
    char *p;

    req.tv_sec = 2;
    req.tv_nsec = 0;

    for(int i = 0;i < 3;i++) {
        p=(char *)malloc(100);
        strncpy(p, "012345678901234567890123456789012345678", 40);
        printf("%s\n",p);
        free(p);
        nanosleep(&req, NULL);
        hello_world();
    }
}