//! Sandbox configuration.
const std = @import("std");

pub const default_binary: [:0]const u8 = "/bin/busybox";
pub const args_max: u32 = 32;

pub const Config = struct {
    binary: [:0]const u8 = default_binary,
    root: ?[]const u8 = null,
    args: [args_max][:0]const u8 = undefined,
    args_count: u32 = 0,
    owns_binary: bool = false,
    owns_root: bool = false,

    pub fn init() Config {
        return .{};
    }

    /// Free any heap-owned strings. Must pass the same allocator used to
    /// duplicate them.
    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        var i: u32 = 0;
        while (i < self.args_count) : (i += 1) {
            allocator.free(self.args[i]);
        }

        if (self.owns_binary) {
            allocator.free(self.binary);
        }

        if (self.owns_root) {
            if (self.root) |r| allocator.free(r);
        }

        self.* = .{};
    }
};

test "Config.init returns defaults" {
    const cfg = Config.init();
    try std.testing.expectEqualStrings("/bin/busybox", cfg.binary);
    try std.testing.expect(cfg.root == null);
    try std.testing.expectEqual(@as(u32, 0), cfg.args_count);
    try std.testing.expect(!cfg.owns_binary);
    try std.testing.expect(!cfg.owns_root);
}

test "Config.deinit frees owned binary" {
    const allocator = std.testing.allocator;
    var cfg = Config.init();
    cfg.binary = try allocator.dupeZ(u8, "/usr/bin/test");
    cfg.owns_binary = true;
    cfg.deinit(allocator);
    try std.testing.expectEqualStrings("/bin/busybox", cfg.binary);
}

test "Config.deinit frees owned root" {
    const allocator = std.testing.allocator;
    var cfg = Config.init();
    cfg.root = try allocator.dupe(u8, "/tmp/test-root");
    cfg.owns_root = true;
    cfg.deinit(allocator);
    try std.testing.expect(cfg.root == null);
}

test "Config.deinit frees args" {
    const allocator = std.testing.allocator;
    var cfg = Config.init();
    cfg.args[0] = try allocator.dupeZ(u8, "ls");
    cfg.args[1] = try allocator.dupeZ(u8, "-la");
    cfg.args_count = 2;
    cfg.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0), cfg.args_count);
}
