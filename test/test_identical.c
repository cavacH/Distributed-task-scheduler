#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <errno.h>

int main(int argc, char *argv[], char *envp[]) {
    char *exe_path = "/home/pi/project/workload";
    int _argc = 4, i;
    char *_argv[4] = {"OTHER", "0", "500", "200000"};
    for(i = 0; i < 30; i++) {
        syscall(__NR_distribute_task, exe_path, _argc, _argv);
        sleep(3);
    }
    return 0;
}
