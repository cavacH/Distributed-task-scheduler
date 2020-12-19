#include <linux/kfifo.h>

#define FIFO_SIZE (ARG_MAX << 5)
#define PROC_FIFO "DTS-fifo"
static DEFINE_MUTEX(read_lock);
static DEFINE_MUTEX(write_lock);
static DECLARE_KFIFO(fifo, unsigned char, FIFO_SIZE);
static DECLARE_WAIT_QUEUE_HEAD(fifo_wq);

static ssize_t fifo_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
	int ret;
	unsigned int copied;

	if (mutex_lock_interruptible(&write_lock))
		return -ERESTARTSYS;

	ret = kfifo_from_user(&fifo, buf, count, &copied);

	mutex_unlock(&write_lock);
    wake_up_interruptible(&fifo_wq);

	return ret ? ret : copied;
}

static ssize_t fifo_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
	int ret;
	unsigned int copied;

	if (mutex_lock_interruptible(&read_lock))
		return -ERESTARTSYS;

	ret = kfifo_to_user(&fifo, buf, count, &copied);

	mutex_unlock(&read_lock);

	return ret ? ret : copied;
}

static const struct file_operations fifo_fops = {
	.owner		= THIS_MODULE,
	.read		= fifo_read,
	.write		= fifo_write,
	.llseek		= noop_llseek,
};