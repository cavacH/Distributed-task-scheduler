#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/udp.h>
#include <linux/inet.h>
#include "tcp_utils.h"
#include "cpu_info_utils.h"

static char *host_ip = "192.168.50.100";
module_param(host_ip, charp, 0644);
static int cpu_sync_period_ms = 1000;
module_param(cpu_sync_period_ms, int, 0644);
static char *exe_root_dir = "/home/pi/exe_folder/";
module_param(exe_root_dir, charp, 0644);

static struct task_struct *cmd_sync = NULL, *cpu_sync = NULL;
static ktime_t cpu_sync_period;
static DEFINE_MUTEX(task_list_lock);
struct task_info {
    pid_t pid;
    struct list_head task_list;
};
static LIST_HEAD(task_list_head);

static void add_task(pid_t task_pid) {
    struct task_info *info;
    mutex_lock(&task_list_lock);
    info = (struct task_info *) kmalloc(sizeof(*info), GFP_KERNEL);
    info->pid = task_pid;
    INIT_LIST_HEAD(&info->task_list);
    list_add(&info->task_list, &task_list_head);
    mutex_unlock(&task_list_lock);
}

static void remove_task(pid_t task_pid) {
    struct task_info *cur;
    mutex_lock(&task_list_lock);
    list_for_each_entry(cur, &task_list_head, task_list) {
        if(cur->pid == task_pid)
            break;
    }
    list_del(&cur->task_list);
    kfree(cur);
    mutex_unlock(&task_list_lock);
}

static void stop_task(pid_t task_pid) {
    char buf[32];
    char *envp[] = {"HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TERM=linux", NULL};
    char *argv[] = {"/bin/sh", "-c", buf};
    sprintf(buf, "kill %d", task_pid);
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static enum hrtimer_restart timer_func(struct hrtimer *t) {
    wake_up_process(cpu_sync);
    hrtimer_forward_now(t, cpu_sync_period);
    return HRTIMER_RESTART;
}

static int cpu_sync_func(void *data) {
    int i, status;
    static char buf_cpu[CPU_SYNC_BUF_SIZE];
    struct cpu_info core[NR_CPUS], cur_stat;
    struct hrtimer timer;
    u64 prev_idle, idle, prev_nonidle, nonidle, prev_total, total, nonidle_diff, total_diff;
    struct socket *sock;
	struct sockaddr_in addr;
	
    /* Initialize CPU sync socket */
	if((status = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock)) < 0) {
		printk(KERN_ERR "%s: Socket creation failed, error = %d\n", current->comm, -status);
		cpu_sync = NULL;
		return -status;
	}
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = in_aton(host_ip);
    addr.sin_port = htons(CPU_SYNC_LISTEN_PORT);
    if((status = kernel_connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr), 0)) < 0) {
        printk(KERN_ERR "%s: Connection failed %pI4:%d, error = %d\n", current->comm, &addr.sin_addr.s_addr, CPU_SYNC_LISTEN_PORT, -status);
        cpu_sync = NULL;
        return -status;
    }
    printk(KERN_INFO "%s: Successfully connect to host\n", current->comm);
    
    /* Initialize CPU collection timer */
    cpu_sync_period = ms_to_ktime(cpu_sync_period_ms);
    hrtimer_init(&timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    timer.function = timer_func;
    for_each_online_cpu(i) {
        get_cpu_stat(&core[i], i);
    }
    hrtimer_start(&timer, cpu_sync_period, HRTIMER_MODE_REL);

    while(!kthread_should_stop()) {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
        memset(buf_cpu, 0, sizeof(buf_cpu));
        for_each_online_cpu(i) {
            get_cpu_stat(&cur_stat, i);

		    prev_idle = core[i].idle + core[i].iowait;
            idle = cur_stat.idle + cur_stat.iowait;
            prev_nonidle = core[i].user + core[i].nice + core[i].system + core[i].irq + core[i].softirq + core[i].steal;
            nonidle = cur_stat.user + cur_stat.nice + cur_stat.system + cur_stat.irq + cur_stat.softirq + cur_stat.steal;
            prev_total = prev_idle + prev_nonidle;
            total = idle + nonidle;
            nonidle_diff = nonidle - prev_nonidle;
            total_diff = total - prev_total;

            core[i] = cur_stat;
            DEBUG_MSG(KERN_INFO, "CPU %d, Nonidle %lld ns, During Last %lld ns\n", i, nonidle_diff, total_diff);
            sprintf(buf_cpu + strlen(buf_cpu), "%lld %lld ", nonidle_diff, total_diff);
	    }
        ktcp_send(sock, buf_cpu, sizeof(buf_cpu), strlen(buf_cpu));
    }
    hrtimer_cancel(&timer);
    msleep(100);
    sock_release(sock);
    return 0;
}

static int receive_file(struct socket *sock, char *path) {
    struct file *f;
    ssize_t write_length;
    int err, size;
    static char buf[CMD_SYNC_BUF_SIZE];
    loff_t offset = 0;

    err = 0;
    sprintf(path, "%s%lld", exe_root_dir, ktime_get());

    printk(KERN_INFO "%s: Ready for receiving executable file from host\n", current->comm);
    f = filp_open(path, O_WRONLY | O_CREAT, 0);
    if(IS_ERR(f)) {
        printk(KERN_ERR "%s: Create exe_file failed\n", current->comm);
        return 1;
    }

    while((size = ktcp_recv(sock, buf, sizeof(buf), NULL)) > 0) {
        write_length = kernel_write(f, buf, size, &offset);
        if(write_length < 0) {
            printk(KERN_ERR "Error: write file error! write_length = %d\n", write_length);
            err = 1;
            break;
        }
        DEBUG_MSG(KERN_INFO, "%s: Write to file %d bytes\n", current->comm, write_length);
    }
    printk(KERN_INFO "%s: Writing executable file done\n", current->comm);

    filp_close(f, NULL);
    return err;
}

static int connection_threadfn(void * data) {
    int delim, len, i, argc, last_space, space_cnt, err;
    struct socket *sock;
    static char title[PATH_MAX], contains[PATH_MAX];
    static char buf[CMD_SYNC_BUF_SIZE], path[PATH_MAX];
    char *envp[] = {"HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TERM=linux", NULL};
    char **argv;
    char *argv2[] = {"/bin/sh", "-c", buf};
    struct subprocess_info *info;
    pid_t cur_pid;

    sock = (struct socket *) data;
    printk(KERN_INFO "%s: New connection thread\n", current->comm);

    while(ktcp_recv(sock, buf, sizeof(buf), NULL) > 0) {
        len = strlen(buf), delim = -1;
        for(i = 0; i < len; ++i) {
            if(buf[i] == ':') {
                delim = i;
                break;
            }
        }
        if(delim == -1) {
            printk(KERN_ERR "%s: Receive unknown packet %s\n", current->comm, buf);
            continue;
        }

        memcpy(title, buf, delim);
        memcpy(contains, buf + delim + 1, len - delim -1);
        title[delim] = '\0';
        contains[len - delim - 1] = '\0';

        DEBUG_MSG(KERN_INFO, "title: %s\n", title);
        DEBUG_MSG(KERN_INFO, "contains: %s\n", contains);

        if(strcmp(title, "CMD") != 0) {
            printk(KERN_ERR "Error: receive unknown packet %s\n", buf);
            continue;
        }
        break;
    }
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "Ready for receive file");
    ktcp_send(sock, buf, sizeof(buf), strlen(buf));
    if(receive_file(sock, path)) {
        printk(KERN_ERR "%s: Receive file error, Ignore request\n", current->comm);
        goto thread_end;
    }
    space_cnt = 0, len = strlen(contains);
    for(i = 0; i < len; i++) 
        space_cnt += (contains[i] == ' ');
    argc = space_cnt + 1;
    argv = (char **) kmalloc(argc * sizeof(char *), GFP_KERNEL);
    argv[0] = (char *) kmalloc(strlen(path) + 1, GFP_KERNEL);
    strcpy(argv[0], path);
    space_cnt = 0, last_space = -1;
    for(i = 0; i < len; i++) {
        if(contains[i] != ' ') continue;
        space_cnt++;
        if(space_cnt == 1) {
            last_space = i;
            continue;
        }
        argv[space_cnt - 1] = (char *) kmalloc(i - last_space, GFP_KERNEL);
        memset(argv[space_cnt - 1], 0, i - last_space);
        memcpy(argv[space_cnt - 1], contains + last_space + 1, i - last_space - 1);
        last_space = i;
    }
    if(argc > 1) {
        argv[space_cnt] = (char *) kmalloc(i - last_space, GFP_KERNEL);
        memset(argv[space_cnt], 0, i - last_space);
        memcpy(argv[space_cnt], contains + last_space + 1, i - last_space - 1);
    }
    sprintf(buf, "chmod +x %s", path); 
    err = call_usermodehelper(argv2[0], argv2, envp, UMH_WAIT_PROC);
    if(err) {
        printk(KERN_ERR "%s: Chmod error: %d\n", current->comm, err);
        goto thread_end;
    }
    
    for(i = 0; i < argc; i++)
        printk(KERN_INFO "%s: Prepare to run, Arg %d: %s\n", current->comm, i, argv[i]);
    msleep(1000);
    printk(KERN_INFO "%s: Task issued\n", current->comm);
    info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if(info == NULL) {
        printk(KERN_ERR "%s: No enough memory\n", current->comm);
        goto thread_end;
    }
    cur_pid = info->pid;
    add_task(cur_pid);
    err = call_usermodehelper_exec(info, UMH_WAIT_PROC | UMH_KILLABLE);
    printk(KERN_INFO "%s: Run status: %d\n", current->comm, err);
    remove_task(cur_pid);

thread_end:
    if(argv != NULL) {
        for(i = 0; i < argc; i++)
            kfree(argv[i]);
        kfree(argv);
    }
    sock_release(sock);
    printk(KERN_INFO "End of TCP connect, release client sock.\n");
    return 0;
}

static int cmd_sync_func(void *data) {
	int status;
    struct socket *sock, *client_sock;
	struct sockaddr_in addr;
    struct inet_connection_sock *isock;
    struct task_struct * connection_thread = NULL;
    struct task_info *cur;
    DECLARE_WAITQUEUE(wq, current);

	if((status = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock)) < 0) {
		printk(KERN_ERR "%s: create ktcp socket failed, error = %d\n", current->comm, -status);
		cmd_sync = NULL;
		return -status;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(CMD_SYNC_LISTEN_IP);
	addr.sin_port = htons(CMD_SYNC_LISTEN_PORT);
	
	if((status = kernel_bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr))) < 0) {
		printk(KERN_ERR "%s: Could not bind or connect to socket, error = %d\n", current->comm, -status);
		sock_release(sock);
		cmd_sync = NULL;
		return -status;
	}

    if((status = kernel_listen(sock, 128)) < 0) {
        printk(KERN_ERR "%s: listen to ktcp socket failed with error %d.\n", current->comm, -status);
        sock_release(sock);
        return -status;
    }
	printk(KERN_INFO "%s: Listening on port %d\n", current->comm, CMD_SYNC_LISTEN_PORT);
    
    isock = inet_csk(sock->sk);

	while(!kthread_should_stop()) {
        if(reqsk_queue_empty(&isock->icsk_accept_queue)) {
            add_wait_queue(&sock->sk->sk_wq->wait, &wq);
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            DEBUG_MSG(KERN_INFO, "icsk queue empty?: %d\n",reqsk_queue_empty(&isock->icsk_accept_queue));
			DEBUG_MSG(KERN_INFO, "recv queue empty?: %d\n",skb_queue_empty(&sock->sk->sk_receive_queue));
            remove_wait_queue(&sock->sk->sk_wq->wait, &wq);
            continue;
        }
        if((status = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &client_sock)) < 0) {
            printk(KERN_ERR "%s: create ktcp client socket failed, error = %d\n", current->comm, -status);
            sock_release(sock);
            return -status;
        }
        if((status = kernel_accept(sock, &client_sock, O_NONBLOCK)) < 0) {
            printk(KERN_ERR "%s: accept ktcp client socket failed with error %d.\n", current->comm, -status);
            sock_release(client_sock);
            continue;
        }
        connection_thread = (struct task_struct *) kthread_create(connection_threadfn, (void *)client_sock, "task_worker");
        if(IS_ERR(connection_thread)) {
            printk(KERN_ERR "%s: Failed to create connection thread: %ld\n", current->comm, PTR_ERR(connection_thread));
            sock_release(client_sock);
            continue;
        }
        wake_up_process(connection_thread);
	}
    mutex_lock(&task_list_lock);
    list_for_each_entry(cur, &task_list_head, task_list) {
        stop_task(cur->pid);
    }
    mutex_unlock(&task_list_lock);
	sock_release(sock);
    return 0;
}

static int sched_slave_init(void) {
    printk(KERN_INFO "sched_slave loaded\n");
	cmd_sync = kthread_create(cmd_sync_func, NULL, "SLAVE_CMD_SERVER");
	if(IS_ERR(cmd_sync)) {
		printk(KERN_ERR "Failed to create SLAVE_CMD_SERVER thread\n");
		return PTR_ERR(cmd_sync);
	}
    cpu_sync = kthread_create(cpu_sync_func, NULL, "SLAVE_CPU_CLIENT");
    if(IS_ERR(cpu_sync)) {
        printk(KERN_ERR "Failed to create SLAVE_CPU_CLIENT thread\n");
		return PTR_ERR(cpu_sync);
    }
    wake_up_process(cpu_sync);
    wake_up_process(cmd_sync);
	return 0;
}

static void sched_slave_exit(void) {
    if(cmd_sync != NULL) {
        kthread_stop(cmd_sync);
    }
    if(cpu_sync != NULL) {
        kthread_stop(cpu_sync);
    }
	printk(KERN_INFO "sched_slave unloaded\n");
}

module_init(sched_slave_init);
module_exit(sched_slave_exit);
MODULE_LICENSE("GPL");
