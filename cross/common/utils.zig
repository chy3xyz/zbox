const std = @import("std");
const types = @import("types.zig");

// ================================
// 路径转换工具
// ================================
/// Windows路径转WSL2路径
pub fn winToWslPath(allocator: std.mem.Allocator, win_path: []const u8) ![]const u8 {
    // 处理C:\path\to\file 格式
    if (win_path.len >= 3 and win_path[1] == ':' and (win_path[2] == '\\' or win_path[2] == '/')) {
        const drive = std.ascii.toLower(win_path[0]);
        const rest = win_path[3..];
        
        // 替换反斜杠为正斜杠
        var normalized = try allocator.alloc(u8, rest.len);
        @memcpy(normalized, rest);
        for (normalized) |*c| {
            if (c.* == '\\') c.* = '/';
        }
        defer allocator.free(normalized);

        return std.fmt.allocPrint(allocator, "/mnt/{c}/{s}", .{drive, normalized});
    }

    // 处理相对路径或者其他格式
    return types.CrossError.InvalidPath;
}

/// WSL2路径转Windows路径
pub fn wslToWinPath(allocator: std.mem.Allocator, wsl_path: []const u8) ![]const u8 {
    // 处理/mnt/c/path/to/file格式
    if (std.mem.startsWith(u8, wsl_path, "/mnt/") and wsl_path.len >= 6 and wsl_path[5] >= 'a' and wsl_path[5] <= 'z') {
        const drive = std.ascii.toUpper(wsl_path[5]);
        const rest = wsl_path[6..];

        // 替换正斜杠为反斜杠
        var normalized = try allocator.alloc(u8, rest.len);
        @memcpy(normalized, rest);
        for (normalized) |*c| {
            if (c.* == '/') c.* = '\\';
        }
        defer allocator.free(normalized);

        return std.fmt.allocPrint(allocator, "{c}:\\{s}", .{drive, normalized});
    }

    return types.CrossError.InvalidPath;
}

/// macOS路径转Lima路径（几乎一致，只需要处理用户目录映射）
pub fn macToLimaPath(allocator: std.mem.Allocator, mac_path: []const u8) ![]const u8 {
    // Lima默认会把/Users挂载到/lima/Users，所以直接返回即可
    // 如果是其他目录，需要确保已经在共享目录配置中
    return try allocator.dupe(u8, mac_path);
}

/// 自动根据系统转换路径
pub fn convertPathToVm(allocator: std.mem.Allocator, vm_type: types.VmType, host_path: []const u8) ![]const u8 {
    return switch (vm_type) {
        .wsl2 => try winToWslPath(allocator, host_path),
        .lima => try macToLimaPath(allocator, host_path),
        .native => try allocator.dupe(u8, host_path),
    };
}

// ================================
// 套接字通信工具
// ================================
/// 连接到Unix套接字
pub fn connectUnixSocket(allocator: std.mem.Allocator, socket_path: []const u8) !std.posix.socket_t {
    const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    errdefer std.posix.close(sock);

    var addr = std.posix.sockaddr.un{
        .family = std.posix.AF.UNIX,
        .path = undefined,
    };
    @memset(&addr.path, 0);
    if (socket_path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..socket_path.len], socket_path);

    try std.posix.connect(sock, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.un));
    return sock;
}

/// 发送数据到套接字，带长度前缀
pub fn sendMsg(sock: std.posix.socket_t, data: []const u8) !void {
    // 先发送4字节的长度大端序
    const len: u32 = @intCast(data.len);
    const len_be = std.mem.nativeToBig(u32, len);
    try std.posix.sendAll(sock, std.mem.asBytes(&len_be), 0);
    
    // 再发送实际数据
    try std.posix.sendAll(sock, data, 0);
}

/// 从套接字接收数据，带长度前缀
pub fn recvMsg(allocator: std.mem.Allocator, sock: std.posix.socket_t) ![]const u8 {
    // 先接收4字节的长度
    var len_be: u32 = undefined;
    try std.posix.recvAll(sock, std.mem.asBytes(&len_be), 0);
    const len = std.mem.bigToNative(u32, len_be);

    if (len == 0) return &.{};
    if (len > 10 * 1024 * 1024) return error.MsgTooLarge; // 最大10MB

    // 接收实际数据
    const data = try allocator.alloc(u8, len);
    errdefer allocator.free(data);
    try std.posix.recvAll(sock, data, 0);

    return data;
}

// ================================
// 环境检测工具
// ================================
/// 检测当前操作系统
pub fn detectOs() std.Target.Os.Tag {
    return @import("builtin").os.tag;
}

/// 检测是否需要使用虚拟化环境
pub fn needVirtualization() bool {
    const os = detectOs();
    return os != .linux;
}

/// 检测WSL2是否可用（仅Windows有效）
pub fn isWsl2Available(allocator: std.mem.Allocator) !bool {
    if (detectOs() != .windows) return false;

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "wsl", "--list", "--verbose" },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return result.term.Exited == 0;
}

/// 检测Lima是否可用（仅macOS有效）
pub fn isLimaAvailable(allocator: std.mem.Allocator) !bool {
    if (detectOs() != .macos) return false;

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "limactl", "--version" },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return result.term.Exited == 0;
}

// 路径规范化与安全校验
// 返回规范化后的绝对路径，如果路径包含穿越特征则返回错误
pub fn canonicalizePath(allocator: Allocator, path: []const u8) ![]const u8 {
    // 首先校验是否为绝对路径
    if (path.len == 0 or path[0] != '/') {
        return error.InvalidAbsolutePath;
    }

    // 栈上缓冲区处理大多数常见路径，避免堆分配
    var stack_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const stack_allocator = fba.allocator();

    // 分割路径为各个组件
    var components = std.ArrayList([]const u8).init(stack_allocator);
    defer components.deinit();

    var it = std.mem.split(u8, path, "/");
    while (it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) {
            continue; // 忽略空路径和当前目录
        } else if (std.mem.eql(u8, component, "..")) {
            // 遇到上级目录，弹出最后一个组件
            if (components.items.len > 0) {
                _ = components.pop();
            } else {
                // 已经在根目录还..，说明是路径穿越攻击
                return error.PathTraversalDetected;
            }
        } else {
            try components.append(component);
        }
    }

    // 重新拼接为规范化路径
    if (components.items.len == 0) {
        return try allocator.dupe(u8, "/");
    }

    var result = std.ArrayList(u8).init(allocator);
    try result.append('/');
    for (components.items, 0..) |component, i| {
        if (i > 0) try result.append('/');
        try result.appendSlice(component);
    }

    return try result.toOwnedSlice();
}

// 检查路径是否在允许的目录范围内
pub fn isPathAllowed(path: []const u8, allowed_dirs: []const []const u8) bool {
    for (allowed_dirs) |dir| {
        if (std.mem.startsWith(u8, path, dir)) {
            // 确保是目录下的路径，而不是前缀匹配（比如 /dir123 匹配 /dir1 的情况）
            if (path.len == dir.len or path[dir.len] == '/') {
                return true;
            }
        }
    }
    return false;
}