//! JSON configuration file parsing for zbox sandboxes.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const PortForward = struct {
    host: u16,
    sandbox: u16,
};

pub const Config = struct {
    name: [:0]const u8,
    binary: [:0]const u8,
    root: [:0]const u8,
    cpu_cores: u32,
    cpu_limit_percent: u32,
    memory_limit_mb: u32,
    port_forwards: []PortForward,
    network_access: bool,

    /// Free all owned string fields and zero the struct.
    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.binary);
        allocator.free(self.root);
        allocator.free(self.port_forwards);
        self.* = undefined;
    }
};

const JsonConfig = struct {
    name: []const u8,
    binary: []const u8,
    root: []const u8,
    cpu_cores: u32,
    cpu_limit_percent: u32,
    memory_limit_mb: u32,
    port_forwards: ?[]const PortForward = null,
    network_access: ?bool = false,
};

/// Load and validate a Config from a JSON file at `path`.
///
/// All fields are required — missing fields cause a parse error.
/// String fields are duped into owned memory via `allocator`.
pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const fd = try posix.openat(posix.AT.FDCWD, path, .{}, 0);
    defer _ = linux.close(fd);

    var statx_buf: linux.Statx = undefined;
    const stat_rc: isize = @bitCast(linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX{ .SIZE = true }, &statx_buf));
    if (stat_rc < 0) return error.InvalidConfig;
    const file_size: usize = @intCast(statx_buf.size);

    const data = try allocator.alloc(u8, file_size);
    defer allocator.free(data);
    var total_read: usize = 0;
    while (total_read < file_size) {
        const n = posix.read(fd, data[total_read..]) catch return error.InvalidConfig;
        if (n == 0) break;
        total_read += n;
    }

    const parsed = try std.json.parseFromSlice(JsonConfig, allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const cfg = parsed.value;

    // Validate all fields before allocating owned copies.
    if (cfg.name.len == 0) return error.InvalidConfig;
    if (cfg.binary.len == 0 or cfg.binary[0] != '/') return error.InvalidConfig;
    if (cfg.root.len == 0 or cfg.root[0] != '/') return error.InvalidConfig;
    if (cfg.cpu_cores == 0) return error.InvalidConfig;
    if (cfg.cpu_limit_percent == 0 or cfg.cpu_limit_percent > 100) return error.InvalidConfig;
    if (cfg.memory_limit_mb == 0) return error.InvalidConfig;

    const name = try allocator.dupeZ(u8, cfg.name);
    errdefer allocator.free(name);

    const binary = try allocator.dupeZ(u8, cfg.binary);
    errdefer allocator.free(binary);

    const root = try allocator.dupeZ(u8, cfg.root);
    errdefer allocator.free(root);

    var port_forwards: []PortForward = &.{};
    if (cfg.port_forwards) |pf_arr| {
        port_forwards = try allocator.alloc(PortForward, pf_arr.len);
        errdefer allocator.free(port_forwards);
        for (pf_arr, 0..) |pf, i| {
            port_forwards[i] = .{ .host = pf.host, .sandbox = pf.sandbox };
        }
    }

    const network_access = cfg.network_access orelse false;

    return Config{
        .name = name,
        .binary = binary,
        .root = root,
        .cpu_cores = cfg.cpu_cores,
        .cpu_limit_percent = cfg.cpu_limit_percent,
        .memory_limit_mb = cfg.memory_limit_mb,
        .port_forwards = port_forwards,
        .network_access = network_access,
    };
}

fn writeTestFile(path: [*:0]const u8, content: []const u8) !void {
    const rc: isize = @bitCast(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644));
    if (rc < 0) return error.TestFileCreateFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var written: usize = 0;
    while (written < content.len) {
        const w = linux.write(fd, content[written..].ptr, content.len - written);
        const w_signed: isize = @bitCast(w);
        if (w_signed < 0) return error.TestFileCreateFailed;
        written += @intCast(w_signed);
    }
}

fn deleteTestFile(path: [*:0]const u8) void {
    _ = linux.unlink(path);
}

test "load — valid config file" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "test-sandbox",
        \\  "root": "/tmp/zbox_root",
        \\  "binary": "/bin/busybox",
        \\  "cpu_cores": 2,
        \\  "cpu_limit_percent": 10,
        \\  "memory_limit_mb": 3,
        \\  "port_forwards": [{"host": 8080, "sandbox": 80}],
        \\  "network_access": true
        \\}
    ;

    const tmp_path = "zig-test-config.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    var cfg = try load(allocator, tmp_path);
    defer cfg.deinit(allocator);

    try std.testing.expectEqualStrings("test-sandbox", cfg.name);
    try std.testing.expectEqualStrings("/bin/busybox", cfg.binary);
    try std.testing.expectEqualStrings("/tmp/zbox_root", cfg.root);
    try std.testing.expectEqual(@as(u32, 2), cfg.cpu_cores);
    try std.testing.expectEqual(@as(u32, 10), cfg.cpu_limit_percent);
    try std.testing.expectEqual(@as(u32, 3), cfg.memory_limit_mb);
    try std.testing.expectEqual(@as(usize, 1), cfg.port_forwards.len);
    try std.testing.expectEqual(@as(u16, 8080), cfg.port_forwards[0].host);
    try std.testing.expectEqual(@as(u16, 80), cfg.port_forwards[0].sandbox);
    try std.testing.expectEqual(true, cfg.network_access);
}

test "Config.deinit frees owned strings" {
    const allocator = std.testing.allocator;

    var cfg = Config{
        .name = try allocator.dupeZ(u8, "my-sandbox"),
        .binary = try allocator.dupeZ(u8, "/bin/sh"),
        .root = try allocator.dupeZ(u8, "/tmp/root"),
        .cpu_cores = 1,
        .cpu_limit_percent = 50,
        .memory_limit_mb = 64,
        .port_forwards = &.{},
        .network_access = true,
    };

    cfg.deinit(allocator);
    // std.testing.allocator detects leaks — if deinit missed a free the
    // test runner would report it as a failure.
}

test "load — rejects empty name" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "",
        \\  "root": "/tmp/root",
        \\  "binary": "/bin/sh",
        \\  "cpu_cores": 1,
        \\  "cpu_limit_percent": 50,
        \\  "memory_limit_mb": 64
        \\}
    ;

    const tmp_path = "zig-test-config-empty-name.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    try std.testing.expectError(error.InvalidConfig, load(allocator, tmp_path));
}

test "load — rejects non-absolute binary" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "sandbox",
        \\  "root": "/tmp/root",
        \\  "binary": "busybox",
        \\  "cpu_cores": 1,
        \\  "cpu_limit_percent": 50,
        \\  "memory_limit_mb": 64
        \\}
    ;

    const tmp_path = "zig-test-config-rel-binary.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    try std.testing.expectError(error.InvalidConfig, load(allocator, tmp_path));
}

test "load — rejects zero cpu_limit_percent" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "sandbox",
        \\  "root": "/tmp/root",
        \\  "binary": "/bin/sh",
        \\  "cpu_cores": 1,
        \\  "cpu_limit_percent": 0,
        \\  "memory_limit_mb": 64
        \\}
    ;

    const tmp_path = "zig-test-config-zero-cpu.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    try std.testing.expectError(error.InvalidConfig, load(allocator, tmp_path));
}

/// 程序化配置构造器
/// 用于不用JSON文件，直接用代码构造配置
pub const Builder = struct {
    allocator: std.mem.Allocator,
    name: ?[:0]const u8 = null,
    binary: ?[:0]const u8 = null,
    root: ?[:0]const u8 = null,
    cpu_cores: u32 = 1,
    cpu_limit_percent: u32 = 100,
    memory_limit_mb: u32 = 64,
    port_forwards: std.ArrayList(PortForward),
    network_access: bool = false,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{
            .allocator = allocator,
            .port_forwards = std.ArrayList(PortForward).init(allocator),
        };
    }

    pub fn deinit(self: *Builder) void {
        if (self.name) |n| self.allocator.free(n);
        if (self.binary) |b| self.allocator.free(b);
        if (self.root) |r| self.allocator.free(r);
        self.port_forwards.deinit();
        self.* = undefined;
    }

    pub fn set_name(self: *Builder, name: []const u8) !*Builder {
        self.name = try self.allocator.dupeZ(u8, name);
        return self;
    }

    pub fn set_binary(self: *Builder, binary_path: []const u8) !*Builder {
        if (binary_path.len == 0 or binary_path[0] != '/') {
            return error.InvalidBinaryPath;
        }
        self.binary = try self.allocator.dupeZ(u8, binary_path);
        return self;
    }

    pub fn set_root(self: *Builder, root_path: []const u8) !*Builder {
        if (root_path.len == 0 or root_path[0] != '/') {
            return error.InvalidRootPath;
        }
        self.root = try self.allocator.dupeZ(u8, root_path);
        return self;
    }

    pub fn set_cpu_cores(self: *Builder, cores: u32) *Builder {
        self.cpu_cores = cores;
        return self;
    }

    pub fn set_cpu_limit(self: *Builder, percent: u32) !*Builder {
        if (percent < 1 or percent > 100) {
            return error.InvalidCpuLimit;
        }
        self.cpu_limit_percent = percent;
        return self;
    }

    pub fn set_memory_limit(self: *Builder, mb: u32) *Builder {
        self.memory_limit_mb = mb;
        return self;
    }

    pub fn enable_network(self: *Builder, enable: bool) *Builder {
        self.network_access = enable;
        return self;
    }

    pub fn add_port_forward(self: *Builder, host_port: u16, sandbox_port: u16) !*Builder {
        try self.port_forwards.append(.{
            .host = host_port,
            .sandbox = sandbox_port,
        });
        return self;
    }

    /// 构建Config结构体，所有权转移给调用者
    /// 调用者需要调用Config.deinit()释放内存
    pub fn build(self: *Builder) !Config {
        if (self.name == null or self.binary == null or self.root == null) {
            return error.MissingRequiredField;
        }

        const port_forwards = try self.port_forwards.toOwnedSlice();
        errdefer self.allocator.free(port_forwards);

        return Config{
            .name = self.name.?,
            .binary = self.binary.?,
            .root = self.root.?,
            .cpu_cores = self.cpu_cores,
            .cpu_limit_percent = self.cpu_limit_percent,
            .memory_limit_mb = self.memory_limit_mb,
            .port_forwards = port_forwards,
            .network_access = self.network_access,
        };
    }
};


test "ConfigBuilder - valid configuration" {
    const allocator = std.testing.allocator;

    var builder = Builder.init(allocator);
    defer builder.deinit();

    const config = try builder
        .set_name("test-sandbox")
        .set_binary("/bin/sh")
        .set_root("/tmp/test-root")
        .set_cpu_cores(2)
        .try set_cpu_limit(75)
        .set_memory_limit(256)
        .enable_network(true)
        .try add_port_forward(8080, 80)
        .try add_port_forward(2222, 22)
        .build();
    defer config.deinit(allocator);

    try std.testing.expectEqualStrings("test-sandbox", config.name);
    try std.testing.expectEqualStrings("/bin/sh", config.binary);
    try std.testing.expectEqualStrings("/tmp/test-root", config.root);
    try std.testing.expectEqual(@as(u32, 2), config.cpu_cores);
    try std.testing.expectEqual(@as(u32, 75), config.cpu_limit_percent);
    try std.testing.expectEqual(@as(u32, 256), config.memory_limit_mb);
    try std.testing.expectEqual(true, config.network_access);
    try std.testing.expectEqual(@as(usize, 2), config.port_forwards.len);
    try std.testing.expectEqual(@as(u16, 8080), config.port_forwards[0].host);
    try std.testing.expectEqual(@as(u16, 80), config.port_forwards[0].sandbox);
    try std.testing.expectEqual(@as(u16, 2222), config.port_forwards[1].host);
    try std.testing.expectEqual(@as(u16, 22), config.port_forwards[1].sandbox);
}

test "ConfigBuilder - validation errors" {
    const allocator = std.testing.allocator;

    // Test missing required fields
    var builder1 = Builder.init(allocator);
    defer builder1.deinit();
    try std.testing.expectError(error.MissingRequiredField, builder1.build());

    // Test invalid binary path (not absolute)
    var builder2 = Builder.init(allocator);
    defer builder2.deinit();
    try std.testing.expectError(error.InvalidBinaryPath, builder2.set_binary("bin/sh"));

    // Test invalid root path (not absolute)
    var builder3 = Builder.init(allocator);
    defer builder3.deinit();
    try std.testing.expectError(error.InvalidRootPath, builder3.set_root("tmp/root"));

    // Test invalid CPU limit (<1)
    var builder4 = Builder.init(allocator);
    defer builder4.deinit();
    try std.testing.expectError(error.InvalidCpuLimit, builder4.set_cpu_limit(0));

    // Test invalid CPU limit (>100)
    var builder5 = Builder.init(allocator);
    defer builder5.deinit();
    try std.testing.expectError(error.InvalidCpuLimit, builder5.set_cpu_limit(101));
}
