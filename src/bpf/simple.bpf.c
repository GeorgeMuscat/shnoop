#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512


// From: https://github.com/torvalds/linux/blob/master/include/linux/uio.h
#define ITER_SOURCE	1	// == WRITE
#define ITER_DEST	0	// == READ

#define WRITE ITER_SOURCE
#define READ ITER_DEST
#define BUFSIZE 256
/* definition of a sample sent to user-space from BPF program */
struct event {
    int count;
    char buf[BUFSIZE];
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


// static int do_tty_write(void *ctx, const char __user *buf, size_t count)
// {
//     int zero = 0, i;
//     struct data_t *data;


//     data = data_map.lookup(&zero);
//     if (!data)
//         return 0;

//     #pragma unroll
//     for (i = 0; i < USER_DATACOUNT; i++) {
//         // bpf_probe_read_user() can only use a fixed size, so truncate to count
//         // in user space:
//         if (bpf_probe_read_user(&data->buf, BUFSIZE, (void *)buf))
//             return 0;
//         if (count > BUFSIZE)
//             data->count = BUFSIZE;
//         else
//             data->count = count;
//         PERF_OUTPUT_CTX
//         if (count < BUFSIZE)
//             return 0;
//         count -= BUFSIZE;
//         buf += BUFSIZE;
//     }

//     return 0;
// };

SEC("kprobe/tty_write")
int do_tty_write(struct pt_regs *ctx) {
	/**
     * kernel_ver <  5.14.0: This will break because from->iter_type is not defined
     */

	/*
		tty_write is used to write to any tty device (including pts).
	 	To snoop on a specific tty efficiently, we should return if the inode
		doesn't match the inode that corresponds with the desired device
	*/

	struct kiocb *iocb = PT_REGS_PARM1(ctx);
	struct iov_iter *from = PT_REGS_PARM2(ctx);
    const struct kvec *kvec;

	// // Same as: iocb->ki_filp->f_inode->i_ino != target_ino
    if (BPF_CORE_READ(iocb, ki_filp, f_inode, i_ino)  != target_ino)
        return 0;


	// // TODO: Explain this
	if (BPF_CORE_READ(from, iter_type) != ITER_IOVEC)
        return 0;

    if (BPF_CORE_READ(from, data_source) != WRITE)
        return 0;

	struct event *e;
	int zero = 0;

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) /* can't happen */
		return 0;
	kvec = BPF_CORE_READ(from, kvec);

	bpf_probe_read_kernel(&e->buf, sizeof(e->buf), &kvec->iov_base);
	bpf_probe_read_kernel(&e->count, sizeof(e->count), &kvec->iov_len);


	// May need to be smart about how this is done, (rb space issues)
	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);

	return 0;
}
// Must have this license or the program will be rejected
char LICENSE[] SEC("license") = "GPL";