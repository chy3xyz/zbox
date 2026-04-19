//! zbox 跨平台客户端，提供和原生zbox完全一致的API
const std = @import("std");
const zbox = @import("zbox");
const common = @import("common");

const protocol = common.protocol;
const types = common.types;
const utils = common.utils;

// 导出和原生zbox完全一致的类型
pub const version = zbox.version;
pub const WaitResult = zbox.WaitResult;
pub const decode_wait_status = zbox.decode_wait_status;
pub const Config = zbox.Config;
pub const PortForward = zbox.PortForward;
pub const Error = zbox.Error || types.CrossError;

// 全局客户端实例，懒加载
var global_client: ?*Client = null;
var client_init_mutex = std.Thread.Mutex{};

/// 客户端核心结构
const Client = struct {
    allocator: std.mem.Allocator,
    sock: std.posix.socket_t,
    vm_type: types.VmType,
    next_request_id: std.atomic.Atomic(u64),
    builder_map: std.AutoHashMap(u64, void), // 跟踪服务端的builder实例
    config_map: std.AutoHashMap(u64, Config), // 跟踪服务端的config实例
    sandbox_map: std.AutoHashMap(u64, void), // 跟踪服务端的sandbox实例

    pub fn init(allocator: std.mem.Allocator) !*Client {
        // 检测是否需要虚拟化
        if (!utils.needVirtualization()) {
            // Linux原生环境，直接返回错误，应该用原生zbox
            return error.NativeLinuxShouldUseZboxDirectly;
        }

        // 初始化虚拟机环境
        const vm_type = try prepareVmEnvironment(allocator);

        // 连接到服务端套接字
        const socket_path = try getVmSocketPath(allocator, vm_type);
        defer allocator.free(socket_path);

        const sock = try utils.connectUnixSocket(allocator, socket_path);

        const self = try allocator.create(Client);
        self.* = .{
            .allocator = allocator,
            .sock = sock,
            .vm_type = vm_type,
            .next_request_id = std.atomic.Atomic(u64).init(1),
            .builder_map = std.AutoHashMap(u64, void).init(allocator),
            .config_map = std.AutoHashMap(u64, Config).init(allocator),
            .sandbox_map = std.AutoHashMap(u64, void).init(allocator),
        };

        return self;
    }

    pub fn deinit(self: *Client) void {
        std.posix.close(self.sock);
        self.builder_map.deinit();
        self.config_map.deinit();
        self.sandbox_map.deinit();
        self.allocator.destroy(self);
    }

    // 发送请求并等待响应
    pub fn sendRequest(self: *Client, method: protocol.ApiMethod, req: anytype) !protocol.ApiResponse {
        const req_id = self.next_request_id.fetchAdd(1, .Monotonic);

        // 序列化请求payload
        const payload = try protocol.serialize(self.allocator, req);
        defer self.allocator.free(payload);

        // 构建请求
        const api_req = protocol.ApiRequest{
            .id = req_id,
            .method = method,
            .payload = payload,
        };
        const req_data = try protocol.serialize(self.allocator, api_req);
        defer self.allocator.free(req_data);

        // 发送请求
        try utils.sendMsg(self.sock, req_data);

        // 接收响应
        const resp_data = try utils.recvMsg(self.allocator, self.sock);
        defer self.allocator.free(resp_data);

        // 反序列化响应
        const api_resp = try protocol.deserialize(self.allocator, protocol.ApiResponse, resp_data);

        if (!api_resp.success) {
            if (api_resp.error) |err_msg| {
                std.log.err("API request failed: {s}", .{err_msg});
            }
            return error.ApiRequestFailed;
        }

        return api_resp;
    }
};

// 获取全局客户端实例，懒加载
fn getGlobalClient(allocator: std.mem.Allocator) !*Client {
    client_init_mutex.lock();
    defer client_init_mutex.unlock();

    if (global_client == null) {
        global_client = try Client.init(allocator);
    }

    return global_client.?;
}

// ================================
// ConfigBuilder 实现，和原生API完全一致
// ================================
pub const ConfigBuilder = struct {
    allocator: std.mem.Allocator,
    builder_id: u64,

    pub fn init(allocator: std.mem.Allocator) ConfigBuilder {
        const client = getGlobalClient(allocator) catch @panic("Failed to initialize zbox client");

        const resp = client.sendRequest(.config_builder_init, protocol.ConfigBuilderInitRequest{}) catch @panic("Failed to create config builder");
        defer client.allocator.free(resp.payload.?);

        const resp_data = protocol.deserialize(client.allocator, protocol.ConfigBuilderInitResponse, resp.payload.?) catch @panic("Failed to parse response");
        defer client.allocator.free(resp_data);

        return ConfigBuilder{
            .allocator = allocator,
            .builder_id = resp_data.builder_id,
        };
    }

    pub fn deinit(self: *ConfigBuilder) void {
        const client = getGlobalClient(self.allocator) catch return;
        _ = client.sendRequest(.config_builder_deinit, protocol.ConfigBuilderDeinitRequest{
            .builder_id = self.builder_id,
        }) catch {};
        self.* = undefined;
    }

    pub fn setName(self: *ConfigBuilder, name: []const u8) !*ConfigBuilder {
        const client = try getGlobalClient(self.allocator);
        _ = try client.sendRequest(.config_builder_set_name, protocol.ConfigBuilderSetNameRequest{
            .builder_id = self.builder_id,
            .name = name,
        });
        return self;
    }

    pub fn setBinary(self: *ConfigBuilder, binary_path: []const u8) !*ConfigBuilder {
        const client = try getGlobalClient(self.allocator);
        // 转换路径到虚拟机内路径
        const vm_path = try utils.convertPathToVm(self.allocator, client.vm_type, binary_path);
        defer self.allocator.free(vm_path);

        _ = try client.sendRequest(.config_builder_set_binary, protocol.ConfigBuilderSetBinaryRequest{
            .builder_id = self.builder_id,
            .binary_path = vm_path,
        });
        return self;
    }

    pub fn setRoot(self: *ConfigBuilder, root_path: []const u8) !*ConfigBuilder {
        const client = try getGlobalClient(self.allocator);
        // 转换路径到虚拟机内路径
        const vm_path = try utils.convertPathToVm(self.allocator, client.vm_type, root_path);
        defer self.allocator.free(vm_path);

        _ = try client.sendRequest(.config_builder_set_root, protocol.ConfigBuilderSetRootRequest{
            .builder_id = self.builder_id,
            .root_path = vm_path,
        });
        return self;
    }

    pub fn setCpuCores(self: *ConfigBuilder, cores: u32) *ConfigBuilder {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.config_builder_set_cpu_cores, protocol.ConfigBuilderSetCpuCoresRequest{
            .builder_id = self.builder_id,
            .cores = cores,
        }) catch @panic("Failed to set cpu cores");
        return self;
    }

    pub fn setCpuLimit(self: *ConfigBuilder, percent: u32) !*ConfigBuilder {
        const client = try getGlobalClient(self.allocator);
        _ = try client.sendRequest(.config_builder_set_cpu_limit, protocol.ConfigBuilderSetCpuLimitRequest{
            .builder_id = self.builder_id,
            .percent = percent,
        });
        return self;
    }

    pub fn setMemoryLimit(self: *ConfigBuilder, mb: u32) *ConfigBuilder {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.config_builder_set_memory_limit, protocol.ConfigBuilderSetMemoryLimitRequest{
            .builder_id = self.builder_id,
            .mb = mb,
        }) catch @panic("Failed to set memory limit");
        return self;
    }

    pub fn enableNetwork(self: *ConfigBuilder, enable: bool) *ConfigBuilder {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.config_builder_enable_network, protocol.ConfigBuilderEnableNetworkRequest{
            .builder_id = self.builder_id,
            .enable = enable,
        }) catch @panic("Failed to set network");
        return self;
    }

    pub fn addPortForward(self: *ConfigBuilder, host_port: u16, sandbox_port: u16) !*ConfigBuilder {
        const client = try getGlobalClient(self.allocator);
        _ = try client.sendRequest(.config_builder_add_port_forward, protocol.ConfigBuilderAddPortForwardRequest{
            .builder_id = self.builder_id,
            .host_port = host_port,
            .sandbox_port = sandbox_port,
        });
        return self;
    }

    pub fn build(self: *ConfigBuilder) !Config {
        const client = try getGlobalClient(self.allocator);
        const resp = try client.sendRequest(.config_builder_build, protocol.ConfigBuilderBuildRequest{
            .builder_id = self.builder_id,
        });
        defer client.allocator.free(resp.payload.?);

        const resp_data = try protocol.deserialize(client.allocator, protocol.ConfigBuilderBuildResponse, resp.payload.?);
        defer client.allocator.free(resp_data);

        // 保存config到map
        try client.config_map.put(resp_data.config_id, resp_data.config);

        return resp_data.config;
    }
};

// ================================
// Sandbox 实现，和原生API完全一致
// ================================
pub const Sandbox = struct {
    allocator: std.mem.Allocator,
    sandbox_id: u64,

    // Args结构体，和原生zbox的Args结构完全一致
    pub const Args = struct {
        config: Config,
        child_args: []const []const u8 = &.{},
        child_args_count: u32 = 0,

        // 兼容旧的构造方式
        pub fn init(config: Config, child_args: ?[]const []const u8) Args {
            return Args{
                .config = config,
                .child_args = child_args orelse &.{},
                .child_args_count = if (child_args) |args| @intCast(args.len) else 0,
            };
        }
    };

    pub fn init(allocator: std.mem.Allocator, args: Args) !Sandbox {
        const client = try getGlobalClient(allocator);

        // 找到对应的config_id
        var config_id: ?u64 = null;
        var iter = client.config_map.iterator();
        while (iter.next()) |entry| {
            if (std.meta.eql(entry.value_ptr.*, args.config)) {
                config_id = entry.key_ptr.*;
                break;
            }
        }
        if (config_id == null) return error.ConfigNotFound;

        // 转换所有child_args中的路径
        var converted_args = std.ArrayList([]const u8).init(allocator);
        defer converted_args.deinit();
        for (args.child_args) |arg| {
            // 尝试转换路径，如果失败就用原始值
            const converted = utils.convertPathToVm(allocator, client.vm_type, arg) catch arg;
            try converted_args.append(converted);
        }

        const resp = try client.sendRequest(.sandbox_init, protocol.SandboxInitRequest{
            .config_id = config_id.?,
            .child_args = converted_args.items,
        });
        defer client.allocator.free(resp.payload.?);

        const resp_data = try protocol.deserialize(client.allocator, protocol.SandboxInitResponse, resp.payload.?);
        defer client.allocator.free(resp_data);

        return Sandbox{
            .allocator = allocator,
            .sandbox_id = resp_data.sandbox_id,
        };
    }

    pub fn deinit(self: *Sandbox) void {
        const client = getGlobalClient(self.allocator) catch return;
        _ = client.sendRequest(.sandbox_deinit, protocol.SandboxDeinitRequest{
            .sandbox_id = self.sandbox_id,
        }) catch {};
        self.* = undefined;
    }

    pub fn setStrictErrors(self: *Sandbox, enable: bool) void {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.sandbox_set_strict_errors, protocol.SandboxSetStrictErrorsRequest{
            .sandbox_id = self.sandbox_id,
            .enable = enable,
        }) catch @panic("Failed to set strict errors");
    }

    pub fn setStdin(self: *Sandbox, fd: std.posix.fd_t) void {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.sandbox_set_stdin, protocol.SandboxSetIoFdRequest{
            .sandbox_id = self.sandbox_id,
            .fd = fd,
        }) catch @panic("Failed to set stdin");
    }

    pub fn setStdout(self: *Sandbox, fd: std.posix.fd_t) void {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.sandbox_set_stdout, protocol.SandboxSetIoFdRequest{
            .sandbox_id = self.sandbox_id,
            .fd = fd,
        }) catch @panic("Failed to set stdout");
    }

    pub fn setStderr(self: *Sandbox, fd: std.posix.fd_t) void {
        const client = getGlobalClient(self.allocator) catch @panic("Client not initialized");
        _ = client.sendRequest(.sandbox_set_stderr, protocol.SandboxSetIoFdRequest{
            .sandbox_id = self.sandbox_id,
            .fd = fd,
        }) catch @panic("Failed to set stderr");
    }

    pub fn spawn(self: *Sandbox) !void {
        const client = try getGlobalClient(self.allocator);
        _ = try client.sendRequest(.sandbox_spawn, protocol.SandboxSpawnRequest{
            .sandbox_id = self.sandbox_id,
        });
    }

    pub fn wait(self: *Sandbox) !WaitResult {
        const client = try getGlobalClient(self.allocator);
        const resp = try client.sendRequest(.sandbox_wait, protocol.SandboxWaitRequest{
            .sandbox_id = self.sandbox_id,
        });
        defer client.allocator.free(resp.payload.?);

        const resp_data = try protocol.deserialize(client.allocator, protocol.SandboxWaitResponse, resp.payload.?);
        defer client.allocator.free(resp_data);

        return resp_data.result;
    }

    // 生命周期回调方法（暂未实现）
    pub fn onPreSpawn(self: *Sandbox, comptime callback: fn (*Sandbox) anyerror!void) void {
        _ = self;
        _ = callback;
        @panic("Callback not implemented yet");
    }

    pub fn onPostSpawn(self: *Sandbox, comptime callback: fn (*Sandbox) anyerror!void) void {
        _ = self;
        _ = callback;
        @panic("Callback not implemented yet");
    }

    pub fn onPreExec(self: *Sandbox, comptime callback: fn (*Sandbox) anyerror!void) void {
        _ = self;
        _ = callback;
        @panic("Callback not implemented yet");
    }

    pub fn onCleanup(self: *Sandbox, comptime callback: fn (*Sandbox) anyerror!void) void {
        _ = self;
        _ = callback;
        @panic("Callback not implemented yet");
    }
};

// ================================
// 虚拟机环境准备相关函数（占位符）
// ================================
fn prepareVmEnvironment(allocator: std.mem.Allocator) !types.VmType {
    const os = utils.detectOs();
    return switch (os) {
        .windows => try prepareWsl2Environment(allocator),
        .macos => try prepareLimaEnvironment(allocator),
        else => error.UnsupportedOs,
    };
}

fn prepareWsl2Environment(allocator: std.mem.Allocator) !types.VmType {
    // TODO: 实现WSL2自动检测、安装、配置
    _ = allocator;
    return types.VmType.wsl2;
}

fn prepareLimaEnvironment(allocator: std.mem.Allocator) !types.VmType {
    // TODO: 实现Lima自动检测、安装、配置
    _ = allocator;
    return types.VmType.lima;
}

fn getVmSocketPath(allocator: std.mem.Allocator, vm_type: types.VmType) ![]const u8 {
    // TODO: 实现不同虚拟机的套接字路径获取
    _ = vm_type;
    return try std.fs.getAppDataDir(allocator, "zbox");
}