#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

volatile int barrier = 1;
pthread_t thread[2];

void *test_thread(void* arg) {
    while (barrier) {
        // make the threads do something
        usleep(10);
    }
    return NULL;
}

void term(int _signum) {
    barrier = 0;

    for (size_t i = 0; i < sizeof(thread)/sizeof(thread[0]); i++) {
        void* result = NULL;
        pthread_join(thread[i], &result);
        if (result != NULL) {
            fprintf(stderr, "thread %zu failed!\n", i);
        }
    }
    puts("OK");
    fflush(stdout);
    exit(0);
}

int main(int argc, char** argv) {
    for (size_t i = 0; i < sizeof(thread)/sizeof(thread[0]); i++) {
        int r = pthread_create(&thread[i], NULL, test_thread, NULL);
        if (r != 0) {
            perror("pthread_create");
        }
    }
    puts("threads started");
    fflush(stdout);

    // threads
    struct sigaction action = {};
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);

    test_thread(0);
    return 0;
}
