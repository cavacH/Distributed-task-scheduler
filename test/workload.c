#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

void work(int iters) {
    struct timespec start_t, end_t;
    int i, magic = 0x3a4b5c6d;
    int64_t x = 1.0, mod = 1e9 + 7;
    double ts_start, ts_end;

    clock_gettime(CLOCK_MONOTONIC, &start_t);
    for(i = 0; i < iters; i++) {
        x = (x * x + (magic ^ i)) % mod; 
    }
    clock_gettime(CLOCK_MONOTONIC, &end_t);
    ts_start = start_t.tv_sec * 1000 + 1.0 * start_t.tv_nsec / 1000000;
    ts_end = end_t.tv_sec * 1000 + 1.0 * end_t.tv_nsec / 1000000;
    printf("time elapsed: %lf ms\n", ts_end - ts_start);
}

void handler(int sig, siginfo_t *si, void *uc) {
    work(si->si_value.sival_int);
}

int main(int argc, char *argv[]) {
    int policy, T, iters, ret;
    struct sigevent evp;
    timer_t timer;
    struct sigaction sa;
    struct itimerspec itv;
    struct sched_param par;
    //cpu_set_t set;

    if(strcmp(argv[1], "RR") == 0) policy = SCHED_RR;
    else if(strcmp(argv[1], "FIFO") == 0) policy = SCHED_FIFO;
    else if(strcmp(argv[1], "OTHER") == 0) policy = SCHED_OTHER;
    else {
        fprintf(stderr, "invalid scheduling class\n");
        exit(EXIT_FAILURE);
    }
    
    par.sched_priority = atoi(argv[2]);
    //core = atoi(argv[3]);
    T = atoi(argv[3]);
    iters = atoi(argv[4]);

    /*CPU_ZERO(&set);
    CPU_SET(core, &set);
    if(sched_setaffinity(0, sizeof(set), &set) == -1) {
        perror("sched_setaffinity");
        exit(EXIT_FAILURE);
    }*/
    if(sched_setscheduler(0, policy, &par) == -1) {
        perror("sched_setscheduler");
        exit(EXIT_FAILURE);
    }
    
    if(T == 0) {
        while(1) work(iters);
    }
    else {
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = handler;
        sigemptyset(&sa.sa_mask);
        if(sigaction(SIGALRM, &sa, NULL) == -1) {
            perror("sigaction");
            exit(EXIT_FAILURE);
        }
        
        evp.sigev_notify = SIGEV_SIGNAL;
        evp.sigev_signo = SIGALRM;
        evp.sigev_value.sival_int = iters;
        if(timer_create(CLOCK_MONOTONIC, &evp, &timer) == -1) {
            perror("timer_create");
            exit(EXIT_FAILURE);
        }

        itv.it_value.tv_sec = T / 1000;
        itv.it_value.tv_nsec = (T % 1000) * 1000000;
        itv.it_interval.tv_sec = itv.it_value.tv_sec;
        itv.it_interval.tv_nsec = itv.it_value.tv_nsec;
        if(timer_settime(timer, 0, &itv, NULL) == -1) {
            perror("timer_settime");
            exit(EXIT_FAILURE);
        }
        while(1) pause();
    }
    return 0;
}
