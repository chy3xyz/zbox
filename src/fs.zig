//! Filesystem utilities

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;
const fs = std.fs;

/// Join `root` and a comptime-known `suffix` into a sentinel-terminated
/// path using the caller's buffer. No heap allocation.
pub fn join_path(
    buf: *[4096]u8,
    root: []const u8,
    comptime suffix: []const u8,
) [:0]const u8 {
    std.debug.assert(root.len > 0 and root[0] == '/');
    return std.fmt.bufPrintZ(buf, "{s}{s}", .{ root, suffix }) catch
        unreachable;
}

/// Extract the filename after the last `/` in an absolute path.
pub fn extract_basename(path: [:0]const u8) []const u8 {
    std.debug.assert(path.len > 0 and path[0] == '/');
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

pub fn write_proc_file(path: [:0]const u8, data: []const u8) !void {
    std.debug.assert(path.len > 0 and path[0] == '/');
    var file = try fs.openFileAbsolute(path, .{ .mode = .write_only });
    defer file.close();
    try file.writeAll(data);
}

pub fn create_dir(dir: [:0]const u8) !void {
    fs.makeDirAbsolute(dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

pub fn create_symlink(target: [:0]const u8, link: [:0]const u8) !void {
    posix.symlink(target, link) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

pub fn bind_mount(source: [:0]const u8, target: [:0]const u8) !void {
    std.debug.assert(source.len > 0 and source[0] == '/');
    std.debug.assert(target.len > 0 and target[0] == '/');
    log.info("bind mounting {s} -> {s}", .{ source, target });

    const rc: isize = @bitCast(linux.syscall5(
        .mount,
        @intFromPtr(source.ptr),
        @intFromPtr(target.ptr),
        @intFromPtr(""),
        4096, // MS_BIND
        0,
    ));
    if (rc < 0) return error.MountFailed;
}

/// Mount a filesystem by type (e.g. "proc", "tmpfs") onto `target`.
pub fn mount_fs(
    comptime fstype: [:0]const u8,
    target: [:0]const u8,
) !void {
    log.info("mounting {s} on {s}", .{ fstype, target });
    const rc: isize = @bitCast(linux.syscall5(
        .mount,
        @intFromPtr(fstype.ptr),
        @intFromPtr(target.ptr),
        @intFromPtr(fstype.ptr),
        0,
        0,
    ));
    if (rc < 0) return error.MountFailed;
}

pub fn generate_root_path(allocator: std.mem.Allocator) ![:0]const u8 {
    const tid = linux.gettid();
    const ts = std.time.milliTimestamp();
    return std.fmt.allocPrintSentinel(allocator, "/tmp/zbox-{d}-{d}", .{ tid, ts }, 0);
}
