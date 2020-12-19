#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <errno.h>

int main(int argc, char *argv[], char *envp[]) {
    char *exe_path = "./workload";
    int _argc = 4, i;
    char *_argv[7][4] = {
        {"OTHER", "0", "1000", "5000000"},
        {"OTHER", "0", "1000", "5000000"},
        {"OTHER", "0", "1000", "200000"},
        {"OTHER", "0", "1000", "300000"},
        {"OTHER", "0", "1000", "400000"},
        {"OTHER", "0", "1000", "500000"},
        {"OTHER", "0", "1000", "600000"},
    };
    for(i = 0; i < 7; i++) {
        syscall(__NR_distribute_task, exe_path, _argc, _argv[i]);
        sleep(3);
    }
    return 0;
}
