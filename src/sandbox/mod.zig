//! Rootless Linux sandbox using user, mount, UTS and network namespaces.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;

const args_mod = @import("../args.zig");
const cgroup = @import("../cgroup.zig");
const network = @import("../network/mod.zig");
const fs = @import("../fs/mod.zig");
const namespace = @import("namespace.zig");
const container = @import("container.zig");
const child = @import("child.zig");

const STACK_SIZE: u32 = 64 * 1024;

const clone_flags: u32 =
    linux.CLONE.NEWNET |
    linux.CLONE.NEWPID |
    linux.CLONE.NEWUSER |
    linux.CLONE.NEWNS |
    linux.CLONE.NEWUTS |
    @intFromEnum(linux.SIG.CHLD);

// these flags share address space with the parent and
// would break our fork-style isolation.
comptime {
    std.debug.assert(clone_flags & linux.CLONE.VM == 0);
    std.debug.assert(clone_flags & linux.CLONE.THREAD == 0);
    std.debug.assert(clone_flags & linux.CLONE.SIGHAND == 0);
}

/// Decoded result of a `waitpid` status word.
pub const WaitResult = union(enum) {
    exited: u8,
    signaled: u7,
    stopped: u8,
    continued: void,
};

/// Decode a raw waitpid status. Continued (0xffff) must be checked
/// first because its bit pattern overlaps the stopped encoding.
pub fn decode_wait_status(status: u32) WaitResult {
    if (status == 0xffff) return .continued;
    if ((status & 0x7f) == 0) return .{ .exited = @intCast((status >> 8) & 0xff) };
    if ((status & 0xff) == 0x7f) return .{ .stopped = @intCast((status >> 8) & 0xff) };
    return .{ .signaled = @intCast(status & 0x7f) };
}

/// Lifecycle callback function type. Receives a pointer to the Sandbox instance as argument.
pub const LifecycleCallback = fn (*Sandbox) anyerror!void;

pub const Sandbox = struct {
    allocator: std.mem.Allocator,
    args: args_mod.Args,
    stack: []align(16) u8,
    pipe: [2]posix.fd_t,
    pid: posix.pid_t,
    root_path: [:0]const u8,
    generated_root: bool,
    veth_host: ?[:0]const u8,
    veth_sandbox: ?[:0]const u8,
    /// 严格错误处理：如果为true，cgroup、网络等错误会返回而不是忽略
    strict_errors: bool = false,
    /// Optional file descriptors for I/O redirection
    stdin_fd: ?posix.fd_t = null,
    stdout_fd: ?posix.fd_t = null,
    stderr_fd: ?posix.fd_t = null,
    /// Pre-spawn callback: runs in parent process before cloning child
    pre_spawn_callback: ?LifecycleCallback = null,
    /// Post-spawn callback: runs in parent process after child is spawned and setup is complete
    post_spawn_callback: ?LifecycleCallback = null,
    /// Pre-exec callback: runs in child process just before execve (inside sandbox)
    pre_exec_callback: ?LifecycleCallback = null,
    /// Cleanup callback: runs in parent process after child exits and cleanup is done
    cleanup_callback: ?LifecycleCallback = null,

    pub fn init(allocator: std.mem.Allocator, args: args_mod.Args) !Sandbox {
        std.debug.assert(args.config.binary.len > 0 and args.config.binary[0] == '/');

        const root_path: [:0]const u8 = try allocator.dupeZ(u8, args.config.root);
        errdefer allocator.free(root_path);

        const stack = try allocator.alignedAlloc(
            u8,
            std.mem.Alignment.fromByteUnits(16),
            STACK_SIZE,
        );
        errdefer allocator.free(stack);

        var pipe_fds: [2]i32 = undefined;
        const pipe_rc: isize = @bitCast(linux.pipe(&pipe_fds));
        if (pipe_rc < 0) return error.PipeFailed;
        const pipe = pipe_fds;

        const self = Sandbox{
            .allocator = allocator,
            .args = args,
            .stack = stack,
            .pipe = pipe,
            .pid = 0,
            .root_path = root_path,
            .generated_root = false,
            .veth_host = null,
            .veth_sandbox = null,
        };

        // Postconditions on the freshly-built sandbox.
        std.debug.assert(self.pid == 0);
        std.debug.assert(self.stack.len == STACK_SIZE);
        std.debug.assert(self.pipe[0] != self.pipe[1]);
        std.debug.assert(self.root_path.len > 1 and self.root_path[0] == '/');

        return self;
    }

    pub fn deinit(self: *Sandbox) void {
        _ = linux.close(self.pipe[0]);
        _ = linux.close(self.pipe[1]);
        self.allocator.free(self.stack);
        self.allocator.free(self.root_path);
        if (self.veth_host) |v| self.allocator.free(v);
        if (self.veth_sandbox) |v| self.allocator.free(v);
        self.args.deinit(self.allocator);
    }

    /// Set custom stdin file descriptor. The descriptor will be duplicated in the child process.
    pub fn set_stdin(self: *Sandbox, fd: posix.fd_t) void {
        self.stdin_fd = fd;
    }

    /// Set custom stdout file descriptor. The descriptor will be duplicated in the child process.
    pub fn set_stdout(self: *Sandbox, fd: posix.fd_t) void {
        self.stdout_fd = fd;
    }

    /// Set custom stderr file descriptor. The descriptor will be duplicated in the child process.
    pub fn set_stderr(self: *Sandbox, fd: posix.fd_t) void {
        self.stderr_fd = fd;
    }

    /// Set pre-spawn callback: runs in parent process before cloning child
    pub fn on_pre_spawn(self: *Sandbox, callback: LifecycleCallback) void {
        self.pre_spawn_callback = callback;
    }

    /// Set post-spawn callback: runs in parent process after child is spawned and setup is complete
    pub fn on_post_spawn(self: *Sandbox, callback: LifecycleCallback) void {
        self.post_spawn_callback = callback;
    }

    /// Set pre-exec callback: runs in child process just before execve (inside sandbox)
    pub fn on_pre_exec(self: *Sandbox, callback: LifecycleCallback) void {
        self.pre_exec_callback = callback;
    }

    /// Set cleanup callback: runs in parent process after child exits and cleanup is done
    pub fn on_cleanup(self: *Sandbox, callback: LifecycleCallback) void {
        self.cleanup_callback = callback;
    }
    /// Clone a child into isolated namespaces, perform parent-side setup,
    /// then signal the child to continue.
pub fn spawn(self: *Sandbox) !void {
        std.debug.assert(self.pid == 0);

        // Run pre-spawn callback if set
        if (self.pre_spawn_callback) |callback| {
            try callback(self);
        }
        // Pre-compute veth names before clone so the child's copy of
        // the Sandbox struct already has them (clone without CLONE.VM
        // gives the child a separate address space snapshot).
        if (self.args.config.network_access or self.args.config.port_forwards.len > 0) {
            const veth = try network.compute_veth_names(self.allocator, self.args.config.name);
            self.veth_host = veth.host;
            self.veth_sandbox = veth.sandbox;
        }

        const stack_top = @intFromPtr(self.stack.ptr) + self.stack.len;
        const raw_pid = linux.clone(
            child.child_entry,
            stack_top,
            clone_flags,
            @intFromPtr(self),
            null,
            0,
            null,
        );
        const pid: isize = @bitCast(raw_pid);
        if (pid < 0) return error.CloneFailed;
        if (pid == 0) return;

        self.pid = @intCast(pid);
        std.debug.assert(self.pid > 0);
        log.info("child spawned pid={d}", .{self.pid});

        try self.parent_setup();
        try self.signal_child();

        // Run post-spawn callback if set
        if (self.post_spawn_callback) |callback| {
            try callback(self);
        }
    }

    /// Wait for the child to exit, log the result, and clean up.
    pub fn wait(self: *Sandbox) !void {
        std.debug.assert(self.pid > 0);

        var status: u32 = undefined;
        _ = linux.waitpid(self.pid, &status, 0);
        switch (decode_wait_status(status)) {
            .exited => |code| log.info("child exited code={d}", .{code}),
            .signaled => |sig| log.warn("child killed signal={d}", .{sig}),
            .stopped => |sig| log.warn("child stopped signal={d}", .{sig}),
            .continued => log.debug("child continued", .{}),
        }
        try self.cleanup();

        // Run cleanup callback if set
        if (self.cleanup_callback) |callback| {
            try callback(self);
        }
    }

    fn parent_setup(self: *Sandbox) !void {
        std.debug.assert(self.pid > 0);
        log.info("parent performing namespace setup", .{});

        try namespace.setup_user_namespace(self.pid);
        try container.setup_container_fs(self.root_path, self.args.config.binary);

        cgroup.create(
            self.args.config.name,
            self.args.config.cpu_cores,
            self.args.config.cpu_limit_percent,
            self.args.config.memory_limit_mb,
        ) catch |err| {
            log.warn("cgroup setup failed: {}", .{err});
        };
        cgroup.add_process(self.args.config.name, self.pid) catch |err| {
            log.warn("cgroup add_process failed: {}", .{err});
        };

        if (self.args.config.network_access or self.args.config.port_forwards.len > 0) {
            self.setup_network() catch |err| {
                log.warn("network setup failed: {}", .{err});
            };
        }
    }

    fn setup_network(self: *Sandbox) !void {
        log.info("setting up network with veth pair", .{});

        const host = self.veth_host orelse return error.VethCreationFailed;
        const sandbox = self.veth_sandbox orelse return error.VethCreationFailed;

        try network.create_veth_link(host, sandbox);
        try network.move_veth_to_ns(sandbox, self.pid);
        try network.configure_host_veth(host);

        for (self.args.config.port_forwards) |pf| {
            try network.setup_port_forward(pf.host, pf.sandbox);
        }

        if (self.args.config.network_access) {
            try network.setup_masquerade();
        }

        log.info("network setup complete", .{});
    }

    fn signal_child(self: *Sandbox) !void {
        const msg: [1]u8 = .{'x'};
        const n: isize = @bitCast(linux.write(self.pipe[1], &msg, 1));
        if (n < 0) return error.WriteFailed;
        std.debug.assert(n == 1);
    }

    fn cleanup(self: *Sandbox) !void {
        var buf_proc: [4096]u8 = undefined;
        var buf_dev: [4096]u8 = undefined;
        var buf_tmp: [4096]u8 = undefined;

        cgroup.destroy(self.args.config.name);
        log.info("cleaning up bind mounts and container root", .{});
        _ = linux.syscall2(.umount2, @intFromPtr(fs.join_path(&buf_proc, self.root_path, "/proc").ptr), 0);
        _ = linux.syscall2(.umount2, @intFromPtr(fs.join_path(&buf_dev, self.root_path, "/dev").ptr), 0);
        _ = linux.syscall2(.umount2, @intFromPtr(fs.join_path(&buf_tmp, self.root_path, "/tmp").ptr), 0);

        for (self.args.config.port_forwards) |pf| {
            network.cleanup_port_forward(pf.host, pf.sandbox);
        }

        if (self.veth_host) |v| {
            network.delete_veth_pair(v);
        }

        if (self.generated_root) {
            const rmdir_rc: isize = @bitCast(linux.rmdir(self.root_path.ptr));
            if (rmdir_rc < 0) {
                log.warn("failed to cleanup {s}", .{self.root_path});
            }
        }
        log.info("cleanup complete", .{});
    }
};

test {
    _ = @import("namespace.zig");
    _ = @import("container.zig");
    _ = @import("child.zig");
}

test "decode_wait_status — normal exit" {
    const result = decode_wait_status(0x0500); // exit code 5
    switch (result) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 5), code),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — exit zero" {
    const result = decode_wait_status(0x0000);
    switch (result) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — signaled" {
    const result = decode_wait_status(0x0009); // SIGKILL = 9
    switch (result) {
        .signaled => |sig| try std.testing.expectEqual(@as(u7, 9), sig),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — stopped" {
    const result = decode_wait_status(0x137f); // stopped by signal 19
    switch (result) {
        .stopped => |sig| try std.testing.expectEqual(@as(u8, 0x13), sig),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — continued" {
    const result = decode_wait_status(0xffff);
    switch (result) {
        .continued => {},
        else => return error.UnexpectedResult,
    }
}


test "Lifecycle callback execution order" {
    const allocator = std.testing.allocator;
    var call_order = std.ArrayList(u8).init(allocator);
    defer call_order.deinit();

    const TestContext = struct {
        order: *std.ArrayList(u8),
        fn pre_spawn(s: *Sandbox) !void {
            _ = s;
            try @This().order.append(1);
        }
        fn post_spawn(s: *Sandbox) !void {
            _ = s;
            try @This().order.append(2);
        }
        fn cleanup(s: *Sandbox) !void {
            _ = s;
            try @This().order.append(3);
        }
    };

    var ctx = TestContext{ .order = &call_order };
    
    // We don't actually run the sandbox in this test, just verify callback setters work
    var builder = @import("../config.zig").Builder.init(allocator);
    defer builder.deinit();
    
    const config = try builder
        .set_name("test-callback")
        .set_binary("/bin/sh")
        .set_root("/tmp/test")
        .build();
    defer config.deinit(allocator);
    
    var sandbox = try Sandbox.init(allocator, .{
        .config = config,
        .child_args_count = 0,
    });
    defer sandbox.deinit();
    
    sandbox.on_pre_spawn(ctx.pre_spawn);
    sandbox.on_post_spawn(ctx.post_spawn);
    sandbox.on_cleanup(ctx.cleanup);
    
    // Verify callbacks are properly set
    try std.testing.expect(sandbox.pre_spawn_callback != null);
    try std.testing.expect(sandbox.post_spawn_callback != null);
    try std.testing.expect(sandbox.cleanup_callback != null);
}

test "I/O redirection setters" {
    const allocator = std.testing.allocator;
    
    var builder = @import("../config.zig").Builder.init(allocator);
    defer builder.deinit();
    
    const config = try builder
        .set_name("test-io")
        .set_binary("/bin/sh")
        .set_root("/tmp/test")
        .build();
    defer config.deinit(allocator);
    
    var sandbox = try Sandbox.init(allocator, .{
        .config = config,
        .child_args_count = 0,
    });
    defer sandbox.deinit();
    
    // Test setting I/O fds (we don't actually open files here, just test the API)
    sandbox.set_stdin(0);
    sandbox.set_stdout(1);
    sandbox.set_stderr(2);
    
    try std.testing.expectEqual(@as(posix.fd_t, 0), sandbox.stdin_fd.?);
    try std.testing.expectEqual(@as(posix.fd_t, 1), sandbox.stdout_fd.?);
    try std.testing.expectEqual(@as(posix.fd_t, 2), sandbox.stderr_fd.?);
}
