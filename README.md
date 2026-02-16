# ebpf-rootkit

Research project for learning eBPF: backdoor agent that gives a remote shell (like SSH) and uses eBPF to hide itself from process listings. The design is informed by real-world eBPF rootkit patterns (e.g. LinkPro-style stealth and trace-hiding).

## Research context

This project aligns with documented incident patterns (kvlnt/vv, vGet/vShell, LinkPro): eBPF-based stealth (getdents64 hiding), optional trace-hiding for spawned shells (`HISTFILE=/tmp/.del` with `/tmp/.del` → `/dev/null`), and TCP-based backdoor access. We do not implement any proprietary or commercial malware; we use free or self-written components only. See **forensics/INCIDENT-KVLNT-VV.md** for incident summary and **forensics/check-artifacts.sh** for IOCs.

## Components

- **rkit-agent** (`.output/rkit-agent`): Main binary (Go). Run with `sudo`. Listens on port 2333, gives a shell to connecting clients. When run as root, loads the getdents64 eBPF hook and hides its own PID from `ps`/`top`/`/proc`. Spawned shells use `HISTFILE=/tmp/.del` (with `/tmp/.del` → `/dev/null`) so history is not written to disk.
- **cli** (C): Client that sends a magic TCP window packet then connects to the agent on port 2333 for an interactive shell.
- **LD_PRELOAD module** (`.output/getdents_preload.so`): LinkPro-style shared library. When loaded via `LD_PRELOAD` or `/etc/ld.so.preload`, hooks `fopen`/`open`, `getdents`/`getdents64`, `readdir`/`readdir64`, and `kill` to hide backdoor artifacts and port 2333 (e.g. `netstat`; `ss` uses netlink and is not affected). Build with `make preload` or `make`.
- **getdents64 hook**: eBPF program attached to `sys_enter_getdents64` / `sys_exit_getdents64` tracepoints. Hides PIDs in the “hidden” set do not appear when listing directories (e.g. `/proc`). Uses `bpf_probe_write_user` to patch the previous entry’s `d_reclen` so the hidden entry is skipped.

## Project layout

- **cmd/rkit-agent/** — Go agent (main, BPF loading, cleanup, persistence, shell handler). Embeds `bpf/*.bpf.o` from `cmd/rkit-agent/bpf/` (populated by `make`).
- **bpf/** — eBPF C sources (getdents hook, hide_bpf, ip_check, ingress_redirect, egress_restore) and `flow_map.h`.
- **cli/** — C client (`main.c`) that sends the magic TCP window packet and connects to the agent.
- **preload/** — LD_PRELOAD hook source (`getdents_preload.c`).
- **config/systemd/** — Optional systemd unit file (`rkit.service`).
- **.output/** — Build output: `rkit-agent`, `cli`, `*.bpf.o`, `getdents_preload.so`.

## Build (Linux)

Requires: **Go**, `clang`, `bpftool`, `libbpf` (and kernel with BTF: `/sys/kernel/btf/vmlinux`).

The agent (`rkit-agent`) is written in Go and embeds the compiled getdents64 BPF object. The Makefile builds the BPF `.bpf.o` from `bpf/*.c`, copies them into `cmd/rkit-agent/bpf/`, then builds the Go binary from `cmd/rkit-agent`.

```bash
make
```

Produces:

- `.output/rkit-agent` — Go agent with embedded eBPF (listens on 2333, loads getdents hook when possible, hides PID when root; spawned shells use HISTFILE=/tmp/.del)
- `.output/getdents_preload.so` — LD_PRELOAD module (LinkPro-style: hide artifacts and port 2333)
- `.output/cli` — C client

## Run

**Agent (target machine, as root):**

```bash
sudo .output/rkit-agent
```

- Listens on `0.0.0.0:2333`.
- If run as root, loads the **Knock** module (XDP + TC): magic TCP window 54321 opens a 1h window; traffic from that IP has its destination port rewritten to 2333 on ingress and source port restored on egress. Set `RKIT_IFACE` (default `eth0`) to the interface with Internet access.
- If run as root, tries to load the eBPF getdents64 hook and hides its own PID. If eBPF fails (e.g. verifier), the agent still runs but the process is not hidden. Spawned shells set `HISTFILE=/tmp/.del` (symlink to `/dev/null`) so command history is not persisted.

**Client (your machine):**

```bash
.output/cli <target_ip>
```

Sends the magic packet, then connects to `<target_ip>:2333` and forwards stdin/stdout for a shell.

### Persistence (LinkPro-style, root only)

To install as a systemd service (disguised as systemd-resolved):

```bash
sudo .output/rkit-agent install
```

This remounts `/` rw, copies the binary to `/usr/lib/.system/.tmp~data.resolveld`, adds `/etc/systemd/system/systemd-resolveld.service`, timestomps the files to match `/etc/passwd`, and runs `systemctl enable systemd-resolveld`.

### Cleanup on exit

On **SIGHUP**, **SIGINT**, or **SIGTERM**, the agent uninstalls: removes TC egress filter and clsact qdisc, detaches XDP, deletes `/sys/fs/bpf/fire`, closes all eBPF programs/links (Hide + getdents), and restores `/etc/ld.so.preload` from `/etc/ld.so.preload.rkit.bak` (if present) and removes `/etc/libld.so`.

## Testing in VM (Multipass Ubuntu 22.04)

Use the **rkit** script from the project root (on your Mac). The VM gets the **full project** mounted at `/workspace`, so you can compile and run everything inside the VM and test for bugs.

If you already have a VM from before, delete and recreate so it gets the full project mount: `./rkit delete` then `./rkit create`.

### One-time setup

1. **Create the VM**
   ```bash
   ./rkit create
   ```
2. **Enter the VM and install build deps** (cloud-init is minimal; install everything after first boot)
   ```bash
   ./rkit shell
   ```
   Inside the VM:
   ```bash
   cd /workspace
   make deps   # installs clang, bpftool, libbpf, etc.
   sudo snap install go --classic   # Go 1.21+
   exit
   ```

### Build and run in the VM

3. **Shell into the VM, build, and run the agent**

   ```bash
   ./rkit shell
   ```

   ```bash
   cd /workspace
   make
   sudo .output/rkit-agent
   ```

   Leave the agent running (or run in background with `&`).

4. **Test the shell from your Mac** (or from another terminal in the VM)
   - Get the VM IP: `multipass list`
   - From your Mac: `.output/cli <vm_ip>` (build first on Mac with `make`, or copy `.output/cli` from the VM)
   - Or from inside the VM (second shell): `./rkit shell` then `.output/cli 127.0.0.1`

   You should get an interactive shell. Try commands, check that the agent process is hidden from `ps`/`top`/`ls /proc` when running as root, and test cleanup (Ctrl+C on the agent, then tc/bpftool state).

### Quick reference

| From host (Mac) | In VM (after `./rkit shell`)  |
| --------------- | ----------------------------- |
| `./rkit create` | Create VM                     |
| `./rkit shell`  | Open shell                    |
| `./rkit test`   | Run tests (binary must exist) |
| `./rkit delete` | Remove VM                     |
|                 | `cd /workspace && make`       |
|                 | `sudo .output/rkit-agent`     |

## getdents64 hook (research notes)

- **Why getdents64:** Tools like `ps` and `top` read `/proc` via `getdents64`. Hiding a PID’s directory there hides the process from those tools.
- **Tracepoints vs kprobe:** The hook uses **tracepoints** (`tp/syscalls/sys_enter_getdents64`, `tp/syscalls/sys_exit_getdents64`) for a stable ABI and to work with `bpf_probe_write_user`.
- **Technique:** On `sys_enter`, the buffer pointer and size are stored keyed by TID. On `sys_exit`, the program walks the filled buffer, finds entries whose name is a numeric PID in the hidden set, and extends the _previous_ entry’s `d_reclen` so the hidden entry is skipped by user-space iteration.
- **Maps:** `hidden_pids` (hash: pid → 1) is filled from userspace; `getdents_ctx_map` (hash: tid → { dirp, count }) passes buffer info from enter to exit; `scratch` is a per-CPU scratch buffer for reading names.

## License

See LICENSE.
