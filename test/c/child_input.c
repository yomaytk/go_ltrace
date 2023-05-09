#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        // Child process
        char input[256];
        printf("Enter some text: ");
        fgets(input, sizeof(input), stdin);
        printf("Child process received: %s", input);
        printf("Second Enter some text: ");
        fgets(input, sizeof(input), stdin);
        printf("Child process received: %s", input);
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        printf("Parent process: Child process finished.\n");
    } else {
        // Fork failed
        perror("Failed to fork");
        return 1;
    }

    return 0;
}
