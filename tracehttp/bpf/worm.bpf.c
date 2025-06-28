// #include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "ctx.h"

char __license[] SEC("license") = "Dual BSD/GPL";

struct event_t {
    __u32 pid;
    __u32 len;
    char buf[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

#define MAX_BUF_SIZE 256  // or 256, depending on your needs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);         // PID
    __type(value, void *);    // buf pointer
    __uint(max_entries, 1024);
} buf_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx) {
    long int target_pid = 391169;
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }

    int fd = ctx->args[0];
    void *buf = (void *)ctx->args[1];
    bpf_map_update_elem(&buf_map, &pid, &buf, BPF_ANY);
    // __u64 raw_count = ctx->args[2];

    // // Explicitly bound the count
    // __u32 safe_count = raw_count & 0x3f; // 0x3f = 63
    // if (safe_count == 0) return 0;

    // char tmp[64] = {};
    // int ret = bpf_probe_read_user(tmp, safe_count, buf);
    // if (ret == 0) {
    //     bpf_printk("read(fd=%d) buf sample: %s\n", fd, tmp);
    // } else {
    //     bpf_printk("read(fd=%d) buf read failed\n", fd);
    // }

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct trace_event_raw_sys_exit *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    void **buf_ptr = bpf_map_lookup_elem(&buf_map, &pid);
    if (!buf_ptr) return 0;

    void *buf = *buf_ptr;
    int bytes = ctx->ret;

    if (bytes <= 0) {
        bpf_map_delete_elem(&buf_map, &pid);
        return 0;
    }

    if (bytes > MAX_BUF_SIZE) bytes = MAX_BUF_SIZE;

    char tmp[MAX_BUF_SIZE] = {};
    int res = bpf_probe_read_user(tmp, bytes, buf);
    if (res == 0) {
        // bpf_printk("read(%d): %s\n", bytes, tmp);
        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if (!e) return 0;
        e->pid = pid;
        // if (bytes > sizeof(e->buf)) bytes = sizeof(e->buf);
        // __builtin_memcpy(e->buf, tmp, sizeof(e->buf));
        // e->buf = tmp;
        bpf_probe_read_kernel(&e->buf, bytes, tmp);
        e->len = bytes;
        bpf_ringbuf_submit(e, 0);
    } else {
        bpf_printk("read(%d): read_user failed\n", bytes);
    }

    bpf_map_delete_elem(&buf_map, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    long int target_pid = 391169;
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }

    int fd = ctx->args[0];
    void *buf = (void *)ctx->args[1];
    bpf_map_update_elem(&buf_map, &pid, &buf, BPF_ANY);
    // __u64 raw_count = ctx->args[2];

    // // Explicitly bound the count
    // __u32 safe_count = raw_count & 0x3f; // 0x3f = 63
    // if (safe_count == 0) return 0;

    // char tmp[64] = {};
    // int ret = bpf_probe_read_user(tmp, safe_count, buf);
    // if (ret == 0) {
    //     bpf_printk("read(fd=%d) buf sample: %s\n", fd, tmp);
    // } else {
    //     bpf_printk("read(fd=%d) buf read failed\n", fd);
    // }

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    void **buf_ptr = bpf_map_lookup_elem(&buf_map, &pid);
    if (!buf_ptr) return 0;

    void *buf = *buf_ptr;
    int bytes = ctx->ret;

    if (bytes <= 0) {
        bpf_map_delete_elem(&buf_map, &pid);
        return 0;
    }

    if (bytes > MAX_BUF_SIZE) bytes = MAX_BUF_SIZE;

    char tmp[MAX_BUF_SIZE] = {};
    int res = bpf_probe_read_user(tmp, bytes, buf);
    if (res == 0) {
        // bpf_printk("read(%d): %s\n", bytes, tmp);
        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if (!e) return 0;
        e->pid = pid;
        // if (bytes > sizeof(e->buf)) bytes = sizeof(e->buf);
        // __builtin_memcpy(e->buf, tmp, sizeof(e->buf));
        // e->buf = tmp;
        bpf_probe_read_kernel(&e->buf, bytes, tmp);
        e->len = bytes;
        bpf_ringbuf_submit(e, 0);
    } else {
        bpf_printk("read(%d): write_user failed\n", bytes);
    }

    bpf_map_delete_elem(&buf_map, &pid);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_execve(struct bpf_raw_tracepoint_args *ctx)
{
    bpf_printk("raw_tracepoint: syscall ID = %d\n", ctx->args[1]);
    return 0;
}


