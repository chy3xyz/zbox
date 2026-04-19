//! Child process entry point and execve logic.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;

const Sandbox = @import("mod.zig").Sandbox;
const args_mod = @import("../args.zig");
const fs = @import("../fs/mod.zig");
const network = @import("../network/mod.zig");
const seccomp = @import("../seccomp.zig");
const container = @import("container.zig");

pub fn child_entry(arg: usize) callconv(.c) u8 {
    std.debug.assert(arg != 0);
    const sandbox_ptr: *Sandbox = @ptrFromInt(arg);

    var buf: [1]u8 = undefined;
    const n = posix.read(sandbox_ptr.pipe[0], &buf) catch |err| {
        log.err("child pipe read failed: {}", .{err});
        return 1;
    };
    if (n == 0) {
        log.err("pipe EOF — parent died before signalling", .{});
        return 1;
    }
    std.debug.assert(n == 1 and buf[0] == 'x');

    // Bind mounts must happen inside the child because CLONE_NEWNS
    // gave *this* process the new mount namespace, not the parent.
    container.child_bind_mounts(sandbox_ptr.root_path) catch |err| {
        log.err("bind mounts failed: {}", .{err});
        return 1;
    };

    // Pivot root instead of chroot for better security
    const pivot_rc = linux.syscall2(.pivot_root, @intFromPtr(sandbox_ptr.root_path.ptr), @intFromPtr("/put_old".ptr));
    if (pivot_rc != 0) {
        // Fallback to chroot if pivot_root fails for any reason
        log.warn("pivot_root failed, falling back to chroot", .{});
        const rc = linux.syscall1(.chroot, @intFromPtr(sandbox_ptr.root_path.ptr));
        if (rc != 0) {
            log.err("chroot failed", .{});
            return 1;
        }
        const chdir_rc: isize = @bitCast(linux.chdir("/"));
        if (chdir_rc < 0) {
            log.err("chdir / failed", .{});
            return 1;
        }
    } else {
        // Pivot root succeeded, unmount the old root
        const umount_rc = linux.syscall2(.umount2, @intFromPtr("/put_old".ptr), linux.MNT.DETACH);
        if (umount_rc < 0) {
            log.warn("failed to unmount /put_old", .{});
        }
    }
    network.bring_up_loopback() catch |err| {
        log.err("loopback failed: {}", .{err});
        return 1;
    };

    if (sandbox_ptr.veth_sandbox) |veth_name| {
        network.configure_sandbox_veth(veth_name) catch |err| {
            log.err("sandbox veth config failed: {}", .{err});
            return 1;
        };
    }

    // Install seccomp filter last — after all privileged setup is done
    // but before execve hands control to untrusted code.
    seccomp.install(sandbox_ptr.args.config.network_access) catch |err| {
        log.err("seccomp install failed: {}", .{err});
        return 1;
    };

    // I/O redirection: override stdin/stdout/stderr if custom fds are provided
    if (sandbox_ptr.stdin_fd) |fd| {
        const dup_rc = linux.dup2(fd, 0);
        if (dup_rc < 0) log.warn("failed to dup2 stdin", .{});
    }
    if (sandbox_ptr.stdout_fd) |fd| {
        const dup_rc = linux.dup2(fd, 1);
        if (dup_rc < 0) log.warn("failed to dup2 stdout", .{});
    }
    if (sandbox_ptr.stderr_fd) |fd| {
        const dup_rc = linux.dup2(fd, 2);
        if (dup_rc < 0) log.warn("failed to dup2 stderr", .{});
    }

    // Run pre-exec callback if set (runs inside sandbox)
    if (sandbox_ptr.pre_exec_callback) |callback| {
        callback(sandbox_ptr) catch |err| {
            log.warn("pre-exec callback failed: {}", .{err});
        }
    }

    return do_execve(sandbox_ptr);
}

/// Build argv from args and call execve. Factored out to keep
/// child_entry under 70 lines.
fn do_execve(sandbox_ptr: *Sandbox) u8 {
    const basename = fs.extract_basename(sandbox_ptr.args.config.binary);
    var bin_buf: [4096]u8 = undefined;
    const bin_path = std.fmt.bufPrintZ(
        &bin_buf,
        "/bin/{s}",
        .{basename},
    ) catch unreachable;
    const bin_ptr: [*:0]const u8 = bin_path.ptr;

    if (sandbox_ptr.args.child_args_count > 0) {
        var argv: [args_mod.args_max + 2]?[*:0]const u8 = undefined;
        argv[0] = bin_ptr;
        var i: u32 = 0;
        while (i < sandbox_ptr.args.child_args_count) : (i += 1) {
            argv[i + 1] = sandbox_ptr.args.child_args[i].ptr;
        }
        argv[sandbox_ptr.args.child_args_count + 1] = null;
        _ = linux.execve(bin_ptr, @ptrCast(&argv), &.{null});
    } else {
        _ = linux.execve(bin_ptr, &.{ bin_ptr, "sh", null }, &.{null});
    }

    log.err("execve failed", .{});
    return 1;
}
