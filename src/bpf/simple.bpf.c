#include <linux/fs.h>
#include <linux/bpf.h>
#include <linux/ptrace.h> // For struct pt_regs
#include <linux/uio.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/* sched_process_exec tracepoint context */
struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	unsigned int __data_loc_filename;
	int pid;
	int old_pid;
	char __data[0];
};

/* definition of a sample sent to user-space from BPF program */
struct event {
	int pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

/* Dummy instance to get skeleton to generate definition for `struct event` */
struct event _event = {0};


// This will be in .RO
const volatile unsigned int target_ino = 0;

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

SEC("ksyscall/execve")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
	struct event *e;
	int zero = 0;

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) /* can't happen */
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32; // Bottom half is the tgid
	bpf_get_current_comm(&e->comm, sizeof(e->comm)); // Get the command
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
	return 0;
}

// SEC("kprobe/tty_write")
int kprobe__tty_write(struct pt_regs *ctx, struct kiocb *iocb,
    struct iov_iter *from)
	{
		bpf_trace_printk("tty_write\n", 11);

	/*
		tty_write is used to write to any tty device (including pts).
	 	To snoop on a specific tty efficiently, we should return if the inode
		doesn't match the inode that corresponds with the desired device
	*/

	// Not sure if this is actually the fp we want
	if (iocb->ki_filp)



	return 0;
}
// Must have this license or the program will be rejected
char LICENSE[] SEC("license") = "GPL";