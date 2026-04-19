//! zbox 服务端，运行在Linux虚拟机内，处理客户端的API请求
const std = @import("std");
const zbox = @import("zbox");
const common = @import("common");

const protocol = common.protocol;
const utils = common.utils;

const Allocator = std.mem.Allocator;

// 全局状态，跟踪所有实例
var global_state: ?*State = null;

const State = struct {
    allocator: Allocator,
    next_id: std.atomic.Atomic(u64),
    builders: std.AutoHashMap(u64, zbox.ConfigBuilder),
    configs: std.AutoHashMap(u64, zbox.Config),
    sandboxes: std.AutoHashMap(u64, zbox.Sandbox),

    pub fn init(allocator: Allocator) !*State {
        const self = try allocator.create(State);
        self.* = .{
            .allocator = allocator,
            .next_id = std.atomic.Atomic(u64).init(1),
            .builders = std.AutoHashMap(u64, zbox.ConfigBuilder).init(allocator),
            .configs = std.AutoHashMap(u64, zbox.Config).init(allocator),
            .sandboxes = std.AutoHashMap(u64, zbox.Sandbox).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *State) void {
        // 清理所有sandbox
        var sandbox_iter = self.sandboxes.valueIterator();
        while (sandbox_iter.next()) |sandbox| {
            sandbox.deinit();
        }
        self.sandboxes.deinit();

        // 清理所有config
        var config_iter = self.configs.valueIterator();
        while (config_iter.next()) |config| {
            config.deinit(self.allocator);
        }
        self.configs.deinit();

        // 清理所有builder
        var builder_iter = self.builders.valueIterator();
        while (builder_iter.next()) |builder| {
            builder.deinit();
        }
        self.builders.deinit();

        self.allocator.destroy(self);
    }

    // 生成新的唯一ID
    fn newId(self: *State) u64 {
        return self.next_id.fetchAdd(1, .Monotonic);
    }
};

// 请求处理函数
fn handleRequest(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    return switch (req.method) {
        // ConfigBuilder 相关请求
        .config_builder_init => handleConfigBuilderInit(state, req),
        .config_builder_set_name => handleConfigBuilderSetName(state, req),
        .config_builder_set_binary => handleConfigBuilderSetBinary(state, req),
        .config_builder_set_root => handleConfigBuilderSetRoot(state, req),
        .config_builder_set_cpu_cores => handleConfigBuilderSetCpuCores(state, req),
        .config_builder_set_cpu_limit => handleConfigBuilderSetCpuLimit(state, req),
        .config_builder_set_memory_limit => handleConfigBuilderSetMemoryLimit(state, req),
        .config_builder_enable_network => handleConfigBuilderEnableNetwork(state, req),
        .config_builder_add_port_forward => handleConfigBuilderAddPortForward(state, req),
        .config_builder_build => handleConfigBuilderBuild(state, req),
        .config_builder_deinit => handleConfigBuilderDeinit(state, req),

        // Sandbox 相关请求
        .sandbox_init => handleSandboxInit(state, req),
        .sandbox_set_strict_errors => handleSandboxSetStrictErrors(state, req),
        .sandbox_set_stdin, .sandbox_set_stdout, .sandbox_set_stderr => handleSandboxSetIoFd(state, req),
        .sandbox_spawn => handleSandboxSpawn(state, req),
        .sandbox_wait => handleSandboxWait(state, req),
        .sandbox_deinit => handleSandboxDeinit(state, req),

        // 回调相关请求（暂未实现）
        else => protocol.ApiResponse{
            .id = req.id,
            .success = false,
            .error = "Method not implemented",
        },
    };
}

// ================================
// ConfigBuilder 请求处理函数
// ================================
fn handleConfigBuilderInit(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    _ = req;
    const builder = zbox.ConfigBuilder.init(state.allocator);
    const builder_id = state.newId();
    try state.builders.put(builder_id, builder);

    const resp = protocol.ConfigBuilderInitResponse{
        .builder_id = builder_id,
    };
    const payload = try protocol.serialize(state.allocator, resp);
    defer state.allocator.free(payload);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
        .payload = payload,
    };
}

fn handleConfigBuilderSetName(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderSetNameRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = try builder.setName(args.name);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderSetBinary(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderSetBinaryRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = try builder.setBinary(args.binary_path);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderSetRoot(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderSetRootRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = try builder.setRoot(args.root_path);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderSetCpuCores(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderSetCpuCoresRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = builder.setCpuCores(args.cores);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderSetCpuLimit(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderSetCpuLimitRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = try builder.setCpuLimit(args.percent);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderSetMemoryLimit(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderSetMemoryLimitRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = builder.setMemoryLimit(args.mb);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderEnableNetwork(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderEnableNetworkRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = builder.enableNetwork(args.enable);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderAddPortForward(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderAddPortForwardRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    _ = try builder.addPortForward(args.host_port, args.sandbox_port);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleConfigBuilderBuild(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderBuildRequest, req.payload);
    defer state.allocator.free(args);

    const builder = state.builders.getPtr(args.builder_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Builder not found",
    };

    const config = try builder.build();
    const config_id = state.newId();
    try state.configs.put(config_id, config);

    const resp = protocol.ConfigBuilderBuildResponse{
        .config_id = config_id,
        .config = config,
    };
    const payload = try protocol.serialize(state.allocator, resp);
    defer state.allocator.free(payload);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
        .payload = payload,
    };
}

fn handleConfigBuilderDeinit(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.ConfigBuilderDeinitRequest, req.payload);
    defer state.allocator.free(args);

    if (state.builders.fetchRemove(args.builder_id)) |entry| {
        var builder = entry.value;
        builder.deinit();
    }

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

// ================================
// Sandbox 请求处理函数
// ================================
fn handleSandboxInit(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.SandboxInitRequest, req.payload);
    defer state.allocator.free(args);

    const config = state.configs.get(args.config_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Config not found",
    };

    const sandbox_args = zbox.Sandbox.Args.init(config, args.child_args);
    const sandbox = try zbox.Sandbox.init(state.allocator, sandbox_args);
    const sandbox_id = state.newId();
    try state.sandboxes.put(sandbox_id, sandbox);

    const resp = protocol.SandboxInitResponse{
        .sandbox_id = sandbox_id,
    };
    const payload = try protocol.serialize(state.allocator, resp);
    defer state.allocator.free(payload);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
        .payload = payload,
    };
}

fn handleSandboxSetStrictErrors(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.SandboxSetStrictErrorsRequest, req.payload);
    defer state.allocator.free(args);

    const sandbox = state.sandboxes.getPtr(args.sandbox_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Sandbox not found",
    };

    sandbox.setStrictErrors(args.enable);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleSandboxSetIoFd(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.SandboxSetIoFdRequest, req.payload);
    defer state.allocator.free(args);

    const sandbox = state.sandboxes.getPtr(args.sandbox_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Sandbox not found",
    };

    // 根据请求方法设置对应的fd
    switch (req.method) {
        .sandbox_set_stdin => sandbox.setStdin(args.fd),
        .sandbox_set_stdout => sandbox.setStdout(args.fd),
        .sandbox_set_stderr => sandbox.setStderr(args.fd),
        else => unreachable,
    }

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleSandboxSpawn(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.SandboxSpawnRequest, req.payload);
    defer state.allocator.free(args);

    const sandbox = state.sandboxes.getPtr(args.sandbox_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Sandbox not found",
    };

    try sandbox.spawn();

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

fn handleSandboxWait(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.SandboxWaitRequest, req.payload);
    defer state.allocator.free(args);

    const sandbox = state.sandboxes.getPtr(args.sandbox_id) orelse return protocol.ApiResponse{
        .id = req.id,
        .success = false,
        .error = "Sandbox not found",
    };

    const result = try sandbox.wait();

    const resp = protocol.SandboxWaitResponse{
        .result = result,
    };
    const payload = try protocol.serialize(state.allocator, resp);
    defer state.allocator.free(payload);

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
        .payload = payload,
    };
}

fn handleSandboxDeinit(state: *State, req: protocol.ApiRequest) !protocol.ApiResponse {
    const args = try protocol.deserialize(state.allocator, protocol.SandboxDeinitRequest, req.payload);
    defer state.allocator.free(args);

    if (state.sandboxes.fetchRemove(args.sandbox_id)) |entry| {
        var sandbox = entry.value;
        sandbox.deinit();
    }

    return protocol.ApiResponse{
        .id = req.id,
        .success = true,
    };
}

// 连接处理协程
fn handleConnection(state: *State, sock: std.posix.socket_t) !void {
    defer std.posix.close(sock);

    while (true) {
        // 接收请求
        const req_data = utils.recvMsg(state.allocator, sock) catch |err| {
            if (err == error.EndOfStream) break; // 连接关闭
            return err;
        };
        defer state.allocator.free(req_data);

        // 反序列化请求
        const req = try protocol.deserialize(state.allocator, protocol.ApiRequest, req_data);
        defer state.allocator.free(req);

        // 处理请求
        const resp = handleRequest(state, req) catch |err| {
            return protocol.ApiResponse{
                .id = req.id,
                .success = false,
                .error = @errorName(err),
            };
        };
        defer if (resp.payload) |p| state.allocator.free(p);
        defer if (resp.error) |e| state.allocator.free(e);

        // 序列化响应
        const resp_data = try protocol.serialize(state.allocator, resp);
        defer state.allocator.free(resp_data);

        // 发送响应
        try utils.sendMsg(sock, resp_data);
    }
}

// 主函数
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 初始化全局状态
    global_state = try State.init(allocator);
    defer global_state.?.deinit();

    // 获取套接字路径，默认是/tmp/zbox.sock
    const socket_path = if (std.os.argv.len > 1) std.mem.span(std.os.argv[1]) else "/tmp/zbox.sock";

    // 删除已存在的套接字
    std.fs.deleteFileAbsolute(socket_path) catch {}

    // 创建Unix套接字
    const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(sock);

    // 绑定套接字
    var addr = std.posix.sockaddr.un{
        .family = std.posix.AF.UNIX,
        .path = undefined,
    };
    @memset(&addr.path, 0);
    if (socket_path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..socket_path.len], socket_path);

    try std.posix.bind(sock, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.un));

    // 监听连接
    try std.posix.listen(sock, 128);

    std.debug.print("zbox server listening on {s}\n", .{socket_path});

    // 接受连接循环
    while (true) {
        const client_sock = try std.posix.accept(sock, null, null, 0);

        // 启动协程处理连接
        try std.Thread.spawn(.{}, handleConnection, .{global_state.?, client_sock});
    }
}