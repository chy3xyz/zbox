# zbox

> work in progress 

Minimal Linux sandbox written in [Zig](https://ziglang.org/).
Allows the execution of a program in an isolated environment with user, mount, and UTS namespaces.

# Requirements

- Linux kernel with namespace support

# Build

```bash
zig build
```

# Running


```bash
zig build run
```


# TODOs

- [x] User namespace with UID/GID mapping
- [x] Mount namespace
- [x] UTS namespace isolation
- [ ] Mount namespace configuration (bind mounts)
- [ ] Filesystem isolation (chroot/pivot_root)
- [ ] Network namespace isolation
- [ ] Syscall filtering (seccomp)
- [ ] OCI compatibility (run container images)
- [ ] Execute target binary 
