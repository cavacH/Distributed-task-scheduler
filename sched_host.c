#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/udp.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include "tcp_utils.h"
#include "kfifo_utils.h"

#define DEBUG_CMD_SYNC_DEST_IP "192.168.50.101"
#define NR_CPU_MAX 8

static int max_slave = 20;
module_param(max_slave, int, 0644);

static struct task_struct *cmd_sync = NULL, *cpu_sync = NULL;

struct slave_info {
    struct list_head slave_list;
    int nr_cpus;
    u64 *latest_nonidle;
    u64 *latest_period;
    u32 src_ip;
};
static LIST_HEAD(slave_list_head);
static DEFINE_MUTEX(slave_lock);

static struct slave_info* find_slave(const u32 slave_ip, int nr_cpus) {
    struct slave_info *ret;
    list_for_each_entry(ret, &slave_list_head, slave_list) {
        if(ret->src_ip == slave_ip) {
            return ret;
        }
    }
    ret = (struct slave_info *) kmalloc(sizeof(struct slave_info), GFP_KERNEL);
    INIT_LIST_HEAD(&ret->slave_list);
    list_add(&ret->slave_list, &slave_list_head);
    ret->src_ip = slave_ip;
    ret->nr_cpus = nr_cpus;
    ret->latest_nonidle = (u64 *) kmalloc(nr_cpus * sizeof(u64), GFP_KERNEL);
    ret->latest_period = (u64 *) kmalloc(nr_cpus * sizeof(u64), GFP_KERNEL);
    printk(KERN_INFO "%s: Slave connected: %pI4\n", current->comm, &slave_ip);
    return ret;
}

static void slave_schedule(u32 *dest_slave_ip) {
    struct slave_info *cur_slave;
    u64 min_nonidle = 1, min_total = 1, nonidle_sum, total_sum;
    int i;
    mutex_lock(&slave_lock);
    /* Slave decision: minimum aggregate utilization rate*/
    list_for_each_entry(cur_slave, &slave_list_head, slave_list) {
        nonidle_sum = total_sum = 0;
        for(i = 0; i < cur_slave->nr_cpus; i++) {
            nonidle_sum += cur_slave->latest_nonidle[i];
            total_sum += cur_slave->latest_period[i];
        }
        if(nonidle_sum * min_total < min_nonidle * total_sum) {
            min_nonidle = nonidle_sum;
            min_total = total_sum;
            *dest_slave_ip = cur_slave->src_ip;
        }
    }
    mutex_unlock(&slave_lock);
}

struct cpu_client_conn_info {
    struct task_struct *client_t;
    struct socket *client_sock;
    int running;
};
static struct cpu_client_conn_info *cpu_client_pool;
static atomic_t cpu_client_cnt;

static int connection_threadfn(void *data) {
    int status, i, len, num_token, last_space;
    u32 cur_ip = 0;
    u64 cur_tokens[NR_CPU_MAX << 1];
    struct slave_info *cur_slave;
    static char buf_cpu[CPU_SYNC_BUF_SIZE];
    struct cpu_client_conn_info *conn_info;
    struct socket *sock;

    conn_info = (struct cpu_client_conn_info *)data;
    sock = conn_info->client_sock;
    conn_info->running = 1;

    while(!kthread_should_stop()) {
        if(ktcp_recv(sock, buf_cpu, sizeof(buf_cpu), &cur_ip) <= 0) break;
        len = strlen(buf_cpu), num_token = 0, last_space = -1;
        memset(cur_tokens, 0, sizeof(cur_tokens));
        for(i = 0; i < len; i++) {
            if(buf_cpu[i] != ' ') continue;
            buf_cpu[i] = '\0';
            status = kstrtou64(buf_cpu + last_space + 1, 10, &cur_tokens[num_token++]);
            if(status != 0) 
                printk(KERN_ERR "CPU_SYNC: Error parsing, status = %d\n", -status);
            else
                DEBUG_MSG(KERN_INFO, "CPU_SYNC: cur_tokens[%d] = %lld\n", num_token - 1, cur_tokens[num_token - 1]);
            buf_cpu[i] = ' ';
            last_space = i;
        }
        mutex_lock(&slave_lock);
        cur_slave = find_slave(cur_ip, num_token >> 1);
        for(i = 0; i < num_token; i++) {
            /* Convert ns to us, preventing overflow while doing multiplication */
            if(i % 2 == 0) 
                cur_slave->latest_nonidle[i >> 1] = cur_tokens[i] >> 10LL;
            else 
                cur_slave->latest_period[i >> 1] = cur_tokens[i] >> 10LL;
        }
        mutex_unlock(&slave_lock);
    }  

    mutex_lock(&slave_lock);
    cur_slave = NULL;
    list_for_each_entry(cur_slave, &slave_list_head, slave_list) {
        if(cur_slave->src_ip == cur_ip) 
            break;
    }
    if(cur_slave != NULL) {
        list_del(&cur_slave->slave_list);
        kfree(cur_slave->latest_nonidle);
        kfree(cur_slave->latest_period);
        kfree(cur_slave);
        printk(KERN_INFO "%s: Slave disconnected: %pI4\n", current->comm, &cur_ip);
    }
    mutex_unlock(&slave_lock);

    sock_release(sock);
    conn_info->running = 0;
    atomic_dec(&cpu_client_cnt);
    return 0;
}

static int cpu_sync_func(void *data) {
    int status, i;
    struct socket *sock, *client_sock;
	struct sockaddr_in addr;
    struct inet_connection_sock *isock;
    DECLARE_WAITQUEUE(wq, current);

	if((status = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock)) < 0) {
		printk(KERN_ERR "%s: Socket creation failed, error = %d\n", current->comm, -status);
		cpu_sync = NULL;
		return -status;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(CPU_SYNC_LISTEN_IP);
	addr.sin_port = htons(CPU_SYNC_LISTEN_PORT);
	
	if((status = kernel_bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr))) < 0) {
		printk(KERN_ERR "%s: Could not bind or connect to socket, error = %d\n", current->comm, -status);
		sock_release(sock);
		cpu_sync = NULL;
		return -status;
	}

    if((status = kernel_listen(sock, 128)) < 0) {
        printk(KERN_ERR "%s: listen to ktcp socket failed with error %d.\n", current->comm, -status);
        sock_release(sock);
        cpu_sync = NULL;
        return -status;
    }
	printk(KERN_INFO "%s: Listening on port %d\n", current->comm, CPU_SYNC_LISTEN_PORT);
    
    isock = inet_csk(sock->sk);

    cpu_client_pool = (struct cpu_client_conn_info *) kmalloc(max_slave * sizeof(struct cpu_client_conn_info), GFP_KERNEL);
    for(i = 0; i < max_slave; i++) {
        memset(&cpu_client_pool[i], 0, sizeof(struct cpu_client_conn_info));
    }
    atomic_set(&cpu_client_cnt, 0);

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
        if(atomic_read(&cpu_client_cnt) == max_slave) {
            printk(KERN_ERR "%s: Reach maximum connection capacity, Ignore request\n", current->comm);
            sock_release(client_sock);
            continue;
        }
        i = 0;
        while(cpu_client_pool[i].running == 1) i++;
        cpu_client_pool[i].client_t = (struct task_struct *) kthread_create(connection_threadfn, (void *)&cpu_client_pool[i], "cpu_client_%d", i);
        if(IS_ERR(cpu_client_pool[i].client_t)) {
            printk(KERN_ERR "%s: Failed to create connection thread: %ld\n", current->comm, PTR_ERR(cpu_client_pool[i].client_t));
            sock_release(client_sock);
            continue;
        }
        cpu_client_pool[i].client_sock = client_sock;
        wake_up_process(cpu_client_pool[i].client_t);
        atomic_inc(&cpu_client_cnt);
    }
    for(i = 0; i < max_slave; i++) {
        if(cpu_client_pool[i].running == 1)
            kthread_stop(cpu_client_pool[i].client_t);
    }
    kfree(cpu_client_pool);
    sock_release(sock);
    return 0;
}

static int send_file(struct socket *sock, char *path) {
    struct file *f;
    ssize_t read_length;
    static char buf[CMD_SYNC_BUF_SIZE];
    loff_t offset = 0;

    printk(KERN_INFO "%s: Ready for send local executable: %s\n", current->comm, path);
    f = filp_open(path, O_RDONLY, 0);
    if(IS_ERR(f)) {
        printk(KERN_ERR "%s: Unable to open file\n", current->comm);
        return 1;
    }
    DEBUG_MSG(KERN_INFO, "%s: open file done\n", current->comm);
    while(true) {
        memset(buf, 0, sizeof(buf));
        read_length = kernel_read(f, buf, sizeof(buf), &offset);
        if (read_length < 0) {
            printk(KERN_ERR "%s: read file error!\n", current->comm);
            break;
        }
        DEBUG_MSG(KERN_INFO, "%s: Read length: %d\n", current->comm, read_length);
        if (ktcp_send(sock, buf, sizeof(buf), read_length) < 0) break;
        if (read_length < sizeof(buf)) break;
    }
    printk(KERN_INFO "%s: Send executable file done\n", current->comm);
    filp_close(f, NULL);
    return 0;
}

static int cmd_sync_func(void *data) {
	int status, read_length, i;
    u32 dest_slave_ip;
    static unsigned char buf[CMD_SYNC_BUF_SIZE], tmp[CMD_SYNC_BUF_SIZE], path[PATH_MAX];
	struct socket *sock;
	struct sockaddr_in addr;
    DECLARE_WAITQUEUE(wq, current);

    while(!kthread_should_stop()) {
        if(kfifo_is_empty(&fifo)) {
            add_wait_queue(&fifo_wq, &wq);
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            remove_wait_queue(&fifo_wq, &wq);
            continue;
        }
        memset(tmp, 0, sizeof(tmp));
        read_length = kfifo_out(&fifo, tmp, sizeof(tmp));
		if (read_length > 0) {
		    printk(KERN_INFO "%s: Read from FIFO %d bytes: %s\n", current->comm, read_length, tmp);
            
            dest_slave_ip = 0;
            if(DEBUG) 
                dest_slave_ip = in_aton(DEBUG_CMD_SYNC_DEST_IP);
            else {
                slave_schedule(&dest_slave_ip);
                if(dest_slave_ip == 0) {
                    printk(KERN_INFO "%s: No available slave, Ignore task\n", current->comm);
                    continue;
                }
                printk(KERN_INFO "%s: Scheduler decision: %pI4\n", current->comm, &dest_slave_ip);
            }

            if((status = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock)) < 0) {
                printk(KERN_ERR "%s: TCP socket creation failed, err = %d\n", current->comm, -status);
                cmd_sync = NULL;
                return -status;
            }
            
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = dest_slave_ip;
            addr.sin_port = htons(CMD_SYNC_LISTEN_PORT);
            
            if((status = kernel_connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr), 0)) < 0) {
                printk(KERN_ERR "%s: Connection failed %pI4:%d, ignore task, error = %d\n", current->comm, &dest_slave_ip, CMD_SYNC_LISTEN_PORT, -status);
                continue;
            }
            printk(KERN_INFO "%s: Connection success\n", current->comm);
            
            memset(path, 0, sizeof(path));
            strcpy(path, tmp);
            for(i = 0; i < read_length; i++) {
                if(tmp[i] != ' ') continue;
                memcpy(path, tmp, i);
                path[i] = '\0';
                break;
            }
            
            memset(buf, 0, sizeof(buf));
            sprintf(buf, "CMD:%s", tmp);
            
            ktcp_send(sock, buf, sizeof(buf), strlen(buf));
            ktcp_recv(sock, buf, sizeof(buf), NULL);
            if(strcmp(buf, "Ready for receive file") == 0) {
                send_file(sock, path);
            }
            msleep(100);
            sock_release(sock);
        }
    }
    return 0;
}

static int sched_host_init(void) {
    printk(KERN_INFO "sched_host loaded\n");
    INIT_KFIFO(fifo);
    if (proc_create(PROC_FIFO, 0666, NULL, &fifo_fops) == NULL)
        return -ENOMEM;

	cmd_sync = kthread_create(cmd_sync_func, NULL, "HOST_CMD_CLIENT");
	if(IS_ERR(cmd_sync)) {
		printk(KERN_ERR "Failed to create HOST_CMD_CLIENT thread\n");
		return PTR_ERR(cmd_sync);
	}
    
    cpu_sync = kthread_create(cpu_sync_func, NULL, "HOST_CPU_SERVER");
    if(IS_ERR(cpu_sync)) {
        printk(KERN_ERR "Failed to create HOST_CPU_SERVER thread\n");
		return PTR_ERR(cpu_sync);
    }
    wake_up_process(cpu_sync);
    wake_up_process(cmd_sync);
	return 0;
}

static void sched_host_exit(void) {
    if(cmd_sync != NULL) {
        kthread_stop(cmd_sync);
    }
    if(cpu_sync != NULL) {
        kthread_stop(cpu_sync);
    }
    remove_proc_entry(PROC_FIFO, NULL);
    mutex_destroy(&read_lock);
    mutex_destroy(&write_lock);
    mutex_destroy(&slave_lock);
    kfifo_free(&fifo);
	printk(KERN_INFO "sched_host unloaded\n");
}

module_init(sched_host_init);
module_exit(sched_host_exit);
MODULE_LICENSE("GPL");
