#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

volatile sig_atomic_t sigint_count = 0;

void sigint_handler(int sig) {
  sigint_count++;
  printf("SIGINT received. Count: %d\n", sigint_count);
  fflush(stdout);

  if (sigint_count >= 3) {
    printf("Exiting...\n");
    exit(0);
  }
}

int main() {
  struct sigaction sa;
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("Error setting SIGINT handler");
    return 1;
  }

  printf("Press Ctrl+C to send a SIGINT signal.\n");

  while (1) {
    pause();
  }

  return 0;
}
