//! Seccomp-BPF syscall filtering for sandboxed processes.
const std = @import("std");
const linux = std.os.linux;
const log = std.log;

const SECCOMP = linux.SECCOMP;

// Classic BPF instruction.
const sock_filter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

// Classic BPF program descriptor passed to seccomp(2).
const sock_fprog = extern struct {
    len: u16,
    filter: [*]const sock_filter,
};

// BPF instruction classes and modes.
const BPF_LD = 0x00;
const BPF_JMP = 0x05;
const BPF_RET = 0x06;
const BPF_W = 0x00;
const BPF_ABS = 0x20;
const BPF_JEQ = 0x10;
const BPF_K = 0x00;

fn bpf_stmt(code: u16, k: u32) sock_filter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) sock_filter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

// Offsets into seccomp_data for BPF loads.
const OFFSET_NR = 0; // offsetof(seccomp_data, nr)
const OFFSET_ARCH = 4; // offsetof(seccomp_data, arch)

/// Syscalls the sandboxed process is NOT allowed to make.
/// This is a deny list approach: default allow, block specific dangerous syscalls.
/// Based on container security best practices and Docker's blocked syscalls.
/// Note: This filter is x86_64-specific (hardcoded syscall numbers and
/// architecture check). Other architectures require different syscall
/// numbers and arch identifiers.
const blocked_syscalls = [_]u32{
    // Kernel module loading - prevents loading malicious kernel modules
    @intFromEnum(linux.SYS.init_module),
    @intFromEnum(linux.SYS.finit_module),
    @intFromEnum(linux.SYS.delete_module),

    // Kernel execution - prevents kexec attacks
    @intFromEnum(linux.SYS.kexec_load),
    @intFromEnum(linux.SYS.kexec_file_load),

    // Hardware access - prevents direct hardware manipulation
    @intFromEnum(linux.SYS.ioperm),
    @intFromEnum(linux.SYS.iopl),
    @intFromEnum(linux.SYS.syslog),

    // Memory management (dangerous variants) - prevents memory manipulation attacks
    @intFromEnum(linux.SYS.mbind),
    @intFromEnum(linux.SYS.set_mempolicy),
    @intFromEnum(linux.SYS.get_mempolicy),
    @intFromEnum(linux.SYS.migrate_pages),
    @intFromEnum(linux.SYS.move_pages),

    // Network syscalls - blocked since we use network namespace isolation
    @intFromEnum(linux.SYS.socket),
    @intFromEnum(linux.SYS.connect),
    @intFromEnum(linux.SYS.accept),
    @intFromEnum(linux.SYS.bind),
    @intFromEnum(linux.SYS.listen),
    @intFromEnum(linux.SYS.sendto),
    @intFromEnum(linux.SYS.recvfrom),
    @intFromEnum(linux.SYS.sendmsg),
    @intFromEnum(linux.SYS.recvmsg),
    @intFromEnum(linux.SYS.accept4),
    @intFromEnum(linux.SYS.shutdown),
    @intFromEnum(linux.SYS.getpeername),
    @intFromEnum(linux.SYS.getsockname),
    @intFromEnum(linux.SYS.getsockopt),
    @intFromEnum(linux.SYS.setsockopt),

    // Device access - prevents creating device nodes
    @intFromEnum(linux.SYS.mknod),
    @intFromEnum(linux.SYS.mknodat),

    // Privilege escalation - prevents changing privileges
    @intFromEnum(linux.SYS.setuid),
    @intFromEnum(linux.SYS.setgid),
    @intFromEnum(linux.SYS.setreuid),
    @intFromEnum(linux.SYS.setregid),
    @intFromEnum(linux.SYS.setresuid),
    @intFromEnum(linux.SYS.setresgid),
    @intFromEnum(linux.SYS.setgroups),
    @intFromEnum(linux.SYS.acct),

    // System control - prevents system manipulation
    @intFromEnum(linux.SYS.reboot),
    @intFromEnum(linux.SYS.swapon),
    @intFromEnum(linux.SYS.swapoff),

    // Time/Alarm - can be used for timing attacks
    @intFromEnum(linux.SYS.setitimer),
    @intFromEnum(linux.SYS.getitimer),
    @intFromEnum(linux.SYS.alarm),

    // Debugging - can be used for information leak
    @intFromEnum(linux.SYS.ptrace),
    @intFromEnum(linux.SYS.process_vm_readv),
    @intFromEnum(linux.SYS.process_vm_writev),

    // Others
    @intFromEnum(linux.SYS.userfaultfd),
    @intFromEnum(linux.SYS.nfsservctl),
    @intFromEnum(linux.SYS.get_kernel_syms),
    @intFromEnum(linux.SYS.query_module),
    @intFromEnum(linux.SYS.request_key),
    @intFromEnum(linux.SYS.keyctl),
    @intFromEnum(linux.SYS.add_key),
};

/// Build the BPF filter program at comptime. The structure is:
///   1. Load arch, reject if not x86_64.
///   2. Load syscall nr.
///   3. For each blocked syscall, jump to KILL if equal.
///   4. Default: ALLOW.
const filter = build_filter();

fn build_filter() [blocked_syscalls.len + 5]sock_filter {
    // 3 (load arch + check arch + load nr) + N (jumps) + 1 (allow) + 1 (kill).
    const n = blocked_syscalls.len;
    var prog: [n + 5]sock_filter = undefined;

    // [0] Load architecture.
    prog[0] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH);
    // [1] If arch != x86_64, jump to kill (skip n+1 instructions).
    // AUDIT_ARCH_X86_64 = 64BIT | LE | EM_X86_64 = 0xC000003E.
    prog[1] = bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        0xC000003E,
        0, // jt: continue to [2]
        @intCast(n + 1), // jf: jump to kill (wrong architecture)
    );
    // [2] Load syscall number.
    prog[2] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);

    // [3..3+n-1] One conditional jump per blocked syscall.
    for (0..n) |i| {
        // Distance to the KILL instruction from this instruction.
        const dist_to_kill: u8 = @intCast(n - i);
        prog[3 + i] = bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            blocked_syscalls[i],
            dist_to_kill, // jt: jump to kill
            0, // jf: continue checking
        );
    }

    // [3+n] Default: allow the syscall (if not blocked).
    prog[3 + n] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.ALLOW);
    // [3+n+1] Kill (for blocked syscalls or wrong architecture).
    prog[3 + n + 1] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.KILL_PROCESS);

    return prog;
}

pub const SeccompError = error{
    SetNoNewPrivsFailed,
    SeccompLoadFailed,
};

/// Install the seccomp filter. Must be called after all privileged
/// setup (mounts, chroot, loopback) but before execve.
pub fn install() SeccompError!void {
    const PR_SET_NO_NEW_PRIVS = 38;

    // seccomp requires NO_NEW_PRIVS to be set first.
    const nnp_rc: isize = @bitCast(linux.prctl(
        PR_SET_NO_NEW_PRIVS,
        1,
        0,
        0,
        0,
    ));
    if (nnp_rc != 0) return error.SetNoNewPrivsFailed;

    const prog = sock_fprog{
        .len = filter.len,
        .filter = &filter,
    };

    const rc: isize = @bitCast(linux.syscall3(
        .seccomp,
        SECCOMP.SET_MODE_FILTER,
        0,
        @intFromPtr(&prog),
    ));
    if (rc < 0) return error.SeccompLoadFailed;

    log.info("seccomp deny list filter installed ({d} dangerous syscalls blocked)", .{blocked_syscalls.len});
}

test "filter is built at comptime" {
    // Verify the filter has the expected length.
    const expected_len = blocked_syscalls.len + 5;
    try std.testing.expectEqual(expected_len, filter.len);

    // First instruction loads arch.
    try std.testing.expectEqual(BPF_LD | BPF_W | BPF_ABS, filter[0].code);
    try std.testing.expectEqual(OFFSET_ARCH, filter[0].k);

    // Second checks x86_64 (AUDIT_ARCH_X86_64 = 0xC000003E).
    try std.testing.expectEqual(@as(u32, 0xC000003E), filter[1].k);

    // Last instruction is KILL_PROCESS (for blocked syscalls).
    try std.testing.expectEqual(SECCOMP.RET.KILL_PROCESS, filter[filter.len - 1].k);

    // Second-to-last is ALLOW (default action).
    try std.testing.expectEqual(SECCOMP.RET.ALLOW, filter[filter.len - 2].k);
}

test "blocked_syscalls contains dangerous syscalls" {
    const dangerous = [_]u32{
        @intFromEnum(linux.SYS.init_module),
        @intFromEnum(linux.SYS.kexec_load),
        @intFromEnum(linux.SYS.socket),
        @intFromEnum(linux.SYS.ptrace),
        @intFromEnum(linux.SYS.reboot),
    };
    for (dangerous) |nr| {
        var found = false;
        for (blocked_syscalls) |b| {
            if (b == nr) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "essential syscalls are not blocked" {
    // These syscalls should NOT be in the blocked list
    const essentials = [_]u32{
        @intFromEnum(linux.SYS.read),
        @intFromEnum(linux.SYS.write),
        @intFromEnum(linux.SYS.execve),
        @intFromEnum(linux.SYS.exit_group),
        @intFromEnum(linux.SYS.brk),
        @intFromEnum(linux.SYS.openat),
    };
    for (essentials) |nr| {
        for (blocked_syscalls) |b| {
            try std.testing.expect(nr != b);
        }
    }
}
