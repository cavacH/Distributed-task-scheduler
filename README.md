# Distributed-task-scheduler
A new kernel feature supporting scheduling tasks to slaves in a load balance manner

## Environment
* 1 Raspberry Pi 3B served as the host machine and at least 1 Raspberry Pi 3B served as slave machines
* Operating System: Linux raspberrypi 5.4.42-v7, armv7l

## Deployment Instructions
* Follow the instructions of https://www.cse.wustl.edu/~cdgill/courses/cse422_fl20/studios/09_syscalls.html to add a new system call sys_distribute_task.c to the kernel (it should be placed under arch/arm/kernel/)
* Recompile the kernel and install it on the host machine
* Compile the kernel modules and install sched_host module on the host   
`sudo insmod sched_host.ko max_slave=10`    
where `max_slave` is a module parameter representing the maximum number of slaves allowed to be connected to the host. You could customize your own parameter based on your own host machine.
* Install sched_slave module on all slave machines  
`sudo insmod sched_slave.ko host_ip="192.168.50.100" cpu_sync_period_ms=1000 exe_root_dir="/home/pi/exe_folder/"`  
where `host_ip` is the Ipv4 address of the host, `cpu_sync_period_ms` is the period in milliseconds of CPU information synchonization from the slave to host, `exe_root_dir` is a folder path to which the executable files should be saved. You could customize your own parameters based on your own slave machines.
* Compile the files in `test/` folder in the repo and you should be able to run `test_identical.c` and `test_uneven.c` on the host machine; You could also customize your own job and own job submission code. After submitting jobs to the host, observe the CPU usage performance on each of the slaves.