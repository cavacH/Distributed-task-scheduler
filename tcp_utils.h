#include <linux/net.h>
#include <linux/wait.h>
#include <linux/limits.h>

#define DEBUG 0
#define DEBUG_MSG(type, fmt, ...) do {if(DEBUG) { printk(type fmt, __VA_ARGS__); }} while(0)
#define CPU_SYNC_LISTEN_IP INADDR_ANY
#define CPU_SYNC_LISTEN_PORT 9001
#define CMD_SYNC_LISTEN_IP INADDR_ANY
#define CMD_SYNC_LISTEN_PORT 4567
#define CPU_SYNC_BUF_SIZE 256
#define CMD_SYNC_BUF_SIZE PATH_MAX

static int ktcp_recv(struct socket *sock, char *buf, size_t buf_size, u32 *src_ip) {
    int ret;
    struct msghdr msg;
    struct kvec vec = {
        .iov_base = buf,
        .iov_len = buf_size
    };
    struct sk_buff *skb;
    DECLARE_WAITQUEUE(wq, current);

    if(skb_queue_empty(&sock->sk->sk_receive_queue)) {
        DEBUG_MSG(KERN_INFO, "%s: Waiting for msg\n", current->comm);
        add_wait_queue(&sock->sk->sk_wq->wait, &wq);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
        remove_wait_queue(&sock->sk->sk_wq->wait, &wq);
        DEBUG_MSG(KERN_INFO, "%s: New msg\n", current->comm);
    }
    if(skb_queue_empty(&sock->sk->sk_receive_queue)) {
        DEBUG_MSG(KERN_INFO, "%s: Woken up by other signals, stop receiving\n", current->comm);
        return 0;
    }

    skb = skb_peek(&sock->sk->sk_receive_queue);
    if(src_ip != NULL) {
        *src_ip = ip_hdr(skb)->saddr;
    }

    memset(&msg, 0, sizeof(struct msghdr));
    memset(buf, 0, buf_size);

    ret = kernel_recvmsg(sock, &msg, &vec, 1, buf_size, 0);
    if(ret < 0) 
        DEBUG_MSG(KERN_ERR, "%s: Failed to receive message\n", current->comm);
    else
        DEBUG_MSG(KERN_INFO, "%s: Received %d bytes from %pI4:%hu : %s\n", current->comm, ret, &ip_hdr(skb)->saddr, tcp_hdr(skb)->source, buf);

    return ret;  
}

static int ktcp_send(struct socket *sock, char *buf, size_t buf_size, size_t data_len) {
    int ret;
    struct msghdr msg;
    struct kvec vec = {        
        .iov_base = buf,
        .iov_len = buf_size
    };
    memset(&msg, 0, sizeof(struct msghdr));
    
    ret = kernel_sendmsg(sock, &msg, &vec, 1, data_len);
    if(ret < 0)
        DEBUG_MSG(KERN_ERR, "%s: Failed to send message\n", current->comm);
    else
        DEBUG_MSG(KERN_INFO, "%s: Send message %d bytes: %s\n", current->comm, ret, buf);

    return ret;
}