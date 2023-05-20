#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    pid_t pid;
    char src_file[100];
    char dest_file[100];
    FILE *src_fp, *dest_fp;
    int ch;
    
    pid = fork();
    
    if (pid == 0) {
        // child process
        printf("Child process (PID=%d) is running.\n", getpid());
        
        // open source file
        printf("input source file path.\n");
        scanf("%s", src_file);
        src_fp = fopen(src_file, "rb");  
        if (src_fp == NULL) {
            perror("fopen error");
            exit(1);
        }
        
        // open dest file
        printf("input dest file path.\n");
        scanf("%s", dest_file);
        dest_fp = fopen(dest_file, "wb");
        if (dest_fp == NULL) {
            perror("fopen error");
            exit(1);
        }
        
        while ((ch = fgetc(src_fp)) != EOF) {
            fputc(ch, dest_fp);  // copy file
        }
        
        fclose(src_fp);
        fclose(dest_fp);
        
        printf("File copy completed.\n");
    } else if (pid > 0) {
        // parent process
        printf("Parent process (PID=%d) created a child process (PID=%d).\n", getpid(), pid);
        int status;
        waitpid(pid, &status, 0);
    } else {
        // fail to fork
        perror("fork failed");
        return 1;
    }
    
    return 0;
}
