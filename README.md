# zbox

[![CI](https://github.com/bxrne/zbox/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/bxrne/zbox/actions/workflows/ci.yml) [![Release](https://github.com/bxrne/zbox/actions/workflows/release.yml/badge.svg?branch=master)](https://github.com/bxrne/zbox/actions/workflows/release.yml)


Minimal rootless Linux sandbox written in [Zig](https://ziglang.org/).

Use cases: build environments, agentic AI sessions, foundation for container runtimes.

Each run creates a fresh, isolated filesystem with its own user/mount/PID/UTS/network namespaces — no sudo required.

## Why Zig?

- **Direct syscall access** — calls Linux syscalls directly without libc, making `clone`, `mount`, `chroot` straightforward
- **No runtime** — no GC, no VM. Produces a tiny static binary ideal for a minimal sandbox
- **Cross-compilation** — built-in support for targeting different architectures

## Requirements

- **x86_64 architecture** — seccomp filter is hardcoded for x86_64 syscall numbers
- **Linux kernel with namespace support** (kernel 5.11+ recommended)
- **Rootless namespaces** — user namespaces must be enabled (check with `sysctl kernel.unprivileged_userns_clone`)
- A statically-linked shell binary (e.g. [busybox](https://busybox.net/)) for testing

### Network Features (Optional)

For `network_access` and `port_forwards`:
- `ip` command (from iproute2 package)
- `iptables`
- Root or `CAP_NET_ADMIN` capability

## Security

### Syscall Filtering

zbox uses **seccomp-BPF with a deny list approach** (similar to Docker's default profile):

- **Default action**: Allow all syscalls
- **Blocked syscalls**: Up to 44 dangerous syscalls are explicitly blocked (29 always, 15 network syscalls conditionally)
- **Blocked categories**:
  - Kernel module loading (`init_module`, `finit_module`, `delete_module`)
  - Kernel execution (`kexec_load`, `kexec_file_load`)
  - Hardware access (`ioperm`, `iopl`, `syslog`)
  - Memory manipulation (`mbind`, `set_mempolicy`, etc.)
  - Network operations (`socket`, `connect`, etc.) — only blocked when `network_access` is disabled; allowed when enabled
  - Device access (`mknod`, `mknodat`)
  - Accounting (`acct`)
  - System control (`reboot`, `swapon`, `swapoff`)
  - Debugging (`ptrace`, `process_vm_readv`, etc.)

### Security Features

- **Architecture check**: Only x86_64 syscalls are processed
- **NO_NEW_PRIVS**: Required before seccomp filter installation
- **Namespace isolation**: User, mount, PID, UTS, and network namespaces
- **Filesystem isolation**: chroot into container root

### busybox

[BusyBox](https://busybox.net/) combines tiny versions of common UNIX utilities (sh, ls, cat, echo, etc.) into a single ~1 MB static binary.  zbox uses it as the default binary executed inside the sandbox for interactive testing.

### Alternatives

- [toybox](https://landley.net/toybox/) — minimal tool suite (used by Android)
- [sbase](http://git.suckless.org/sbase/) — suckless community tools
- Static builds of coreutils

## Build

```bash
zig build
```

## Test

```bash
zig build test
```

## Running

```bash
./zig-out/bin/zbox --config config.json
```

## Options

- `-c, --config <path>` — Path to JSON config file (required)
- `-h, --help` — Show help
- `--` — Forward remaining arguments to the sandboxed binary

## Configuration

Configure via JSON file passed with `-c/--config`:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Sandbox identifier (used for cgroup name) |
| `binary` | string | Absolute path to executable inside sandbox |
| `root` | string | Absolute path to sandbox root directory |
| `cpu_cores` | u32 | Number of CPU cores to allow |
| `cpu_limit_percent` | u32 | CPU limit as percentage (1-100) |
| `memory_limit_mb` | u32 | Memory limit in megabytes |
| `network_access` | bool | Enable internet access from sandbox (default: false) |
| `port_forwards` | array | Port mappings for accessing services inside sandbox |

### Port Forwards

| Field | Type | Description |
|-------|------|-------------|
| `host` | u16 | Port on host to listen on |
| `sandbox` | u16 | Port inside sandbox to forward to |

Example:

```json
{
  "name": "zbox-sandbox",
  "root": "/tmp/zbox_root",
  "binary": "/bin/busybox",
  "cpu_cores": 2,
  "cpu_limit_percent": 10,
  "memory_limit_mb": 3,
  "network_access": true,
  "port_forwards": [
    { "host": 8080, "sandbox": 80 },
    { "host": 2222, "sandbox": 22 }
  ]
}
```

### Network Access

When `network_access: true` is set:
- A veth pair is created connecting the sandbox to the host
- Sandbox gets IP `10.0.2.2/24`
- Host gets IP `10.0.2.1/24`
- NAT/masquerading is enabled allowing the sandbox to access the internet
- Port forwards allow services inside the sandbox to be accessed from the host

**Requirements for network features:**
- `ip` command (iproute2 package)
- `iptables` 
- Root or `CAP_NET_ADMIN` capability for network operations

## Privileged Features (cgroups & networking)

zbox uses Linux cgroups v2 for CPU and memory limits and veth pairs for networking. **These features require sudo** (or `CAP_NET_ADMIN`) because cgroup files in `/sys/fs/cgroup/` and network device management are root-only:

```bash
sudo ./zig-out/bin/zbox -c config.json
```

### Rootless Mode

Without sudo, the sandbox runs but **resource limits and network features are not applied**:

- **cgroups (CPU/memory limits)** — the kernel does not allow unprivileged users to create or manage cgroups. This is a fundamental Linux limitation; all container tools (Docker, Podman, etc.) require root for resource limits.
- **Network access and port forwarding** — creating veth pairs, configuring IP addresses, and setting up iptables rules all require root or `CAP_NET_ADMIN`. Without privileges, `network_access` and `port_forwards` are silently skipped.

The sandbox still provides full isolation via namespaces (user, mount, PID, UTS, network) and seccomp filtering, but CPU/memory constraints and networking require privileged access.

## Roadmap

- [x] User namespace with UID/GID mapping (rootless)
- [x] Mount namespace
- [x] UTS namespace isolation
- [x] Filesystem isolation (chroot)
- [x] PID namespace isolation
- [x] Mounts (proc, tmpfs for /dev and /tmp)
- [x] Execute target binary
- [x] Copy configured binary into container
- [x] Fresh filesystem per run
- [x] Interactive shell (stdin/stdout)
- [x] Network namespace isolation
- [x] Syscall filtering (seccomp-BPF deny list)
- [x] Resource limits (CPU, Memory via cgroups, requires sudo)
- [x] Network access (NAT/masquerading)
- [x] Port forwarding (veth + iptables)
- [x] pivot_root (more secure than chroot)
- [ ] OCI compatibility (run container images)

## Library Usage

zbox can be embedded as a library in other Zig projects. Here's a basic example:

```zig
const std = @import("std");
const zbox = @import("zbox");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Build configuration programmatically
    var config_builder = zbox.ConfigBuilder.init(allocator);
    defer config_builder.deinit();

    const config = try config_builder
        .set_name("my-sandbox")
        .set_root("/tmp/sandbox-root")
        .set_binary("/bin/sh")
        .set_cpu_cores(1)
        .set_cpu_limit(50) // 50% CPU limit
        .set_memory_limit(128) // 128 MB memory limit
        .enable_network(false)
        .build();
    defer config.deinit(allocator);

    // Create sandbox instance
    var sandbox = try zbox.Sandbox.init(allocator, .{
        .config = config,
        .child_args_count = 0,
    });
    defer sandbox.deinit();

    // Optional: Enable strict error handling (fail on cgroup/network setup errors)
    sandbox.set_strict_errors(true);

    // Optional: I/O redirection
    // const stdout_fd = try std.posix.open("sandbox-output.log", .{ .WRONLY, .CREAT, .TRUNC }, 0o644);
    // sandbox.set_stdout(stdout_fd);

    // Optional: Add lifecycle callbacks
    // sandbox.on_pre_spawn(struct {
    //     fn callback(s: *zbox.Sandbox) !void {
    //         std.debug.print("About to spawn sandbox\n", .{});
    //     }
    // }.callback);

    // Run sandbox
    try sandbox.spawn();
    const result = try sandbox.wait();

    switch (result) {
        .exited => |code| std.debug.print("Sandbox exited with code: {}\n", .{code}),
        .signaled => |sig| std.debug.print("Sandbox killed by signal: {}\n", .{sig}),
        else => {},
    }
}
```

## knot3bot Integration

zbox is designed to be embedded in knot3bot to provide secure isolation for untrusted code execution:

1. Add zbox as a dependency in your `build.zig.zon`
2. Use the `ConfigBuilder` API to dynamically create sandbox configurations for each execution
3. Set CPU/memory limits appropriate for your workload
4. Use I/O redirection to capture code output and errors
5. Use lifecycle callbacks to inject custom preparation/cleanup steps

### Security Considerations for knot3bot
- Always run with `strict_errors = true` to catch privilege-related setup failures
- Disable network access unless explicitly required for the workload
- Use the smallest possible CPU/memory limits that still allow your workload to run
- Ensure the sandbox root directory is empty and not used by other processes

## API Reference

### `zbox.ConfigBuilder`
- `init(allocator: std.mem.Allocator)`: Create new builder instance
- `set_name(name: []const u8)`: Set sandbox name (used for cgroup)
- `set_binary(path: []const u8)`: Set path to binary to execute inside sandbox (must be absolute)
- `set_root(path: []const u8)`: Set path to sandbox root directory (must be absolute)
- `set_cpu_cores(cores: u32)`: Set number of CPU cores available
- `set_cpu_limit(percent: u32)`: Set CPU usage limit (1-100)
- `set_memory_limit(mb: u32)`: Set memory limit in megabytes
- `enable_network(enable: bool)`: Enable/disable network access
- `add_port_forward(host_port: u16, sandbox_port: u16)`: Add port forwarding rule
- `build()`: Build `Config` instance (ownership transfers to caller, must call `deinit()` when done)

### `zbox.Sandbox`
- `init(allocator: std.mem.Allocator, args: Args)`: Create new sandbox instance
- `deinit()`: Clean up sandbox resources
- `set_strict_errors(enable: bool)`: Enable/disable strict error mode
- `set_stdin(fd: posix.fd_t)`, `set_stdout(fd: posix.fd_t)`, `set_stderr(fd: posix.fd_t)`: Set custom I/O file descriptors
- `on_pre_spawn(callback: LifecycleCallback)`, `on_post_spawn(callback: LifecycleCallback)`, `on_pre_exec(callback: LifecycleCallback)`, `on_cleanup(callback: LifecycleCallback)`: Set lifecycle callbacks
- `spawn()`: Spawn sandbox child process
- `wait()`: Wait for child to exit and perform cleanup, returns `WaitResult`
