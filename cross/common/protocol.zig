const std = @import("std");
const zbox = @import("zbox");

// API 方法枚举
pub const ApiMethod = enum {
    // ConfigBuilder 方法
    config_builder_init,
    config_builder_set_name,
    config_builder_set_binary,
    config_builder_set_root,
    config_builder_set_cpu_cores,
    config_builder_set_cpu_limit,
    config_builder_set_memory_limit,
    config_builder_enable_network,
    config_builder_add_port_forward,
    config_builder_build,
    config_builder_deinit,

    // Sandbox 方法
    sandbox_init,
    sandbox_set_strict_errors,
    sandbox_set_stdin,
    sandbox_set_stdout,
    sandbox_set_stderr,
    sandbox_on_pre_spawn,
    sandbox_on_post_spawn,
    sandbox_on_pre_exec,
    sandbox_on_cleanup,
    sandbox_spawn,
    sandbox_wait,
    sandbox_deinit,
};

// 统一请求格式
pub const ApiRequest = struct {
    id: u64, // 请求ID，用来匹配响应
    method: ApiMethod,
    payload: []const u8, // 序列化后的参数
};

// 统一响应格式
pub const ApiResponse = struct {
    id: u64, // 对应请求ID
    success: bool,
    error: ?[]const u8 = null,
    payload: ?[]const u8 = null, // 序列化后的返回数据
};

// ================================
// ConfigBuilder 相关请求/响应
// ================================
pub const ConfigBuilderInitRequest = struct {};
pub const ConfigBuilderInitResponse = struct {
    builder_id: u64, // 服务端生成的builder唯一ID
};

pub const ConfigBuilderSetNameRequest = struct {
    builder_id: u64,
    name: []const u8,
};

pub const ConfigBuilderSetBinaryRequest = struct {
    builder_id: u64,
    binary_path: []const u8,
};

pub const ConfigBuilderSetRootRequest = struct {
    builder_id: u64,
    root_path: []const u8,
};

pub const ConfigBuilderSetCpuCoresRequest = struct {
    builder_id: u64,
    cores: u32,
};

pub const ConfigBuilderSetCpuLimitRequest = struct {
    builder_id: u64,
    percent: u32,
};

pub const ConfigBuilderSetMemoryLimitRequest = struct {
    builder_id: u64,
    mb: u32,
};

pub const ConfigBuilderEnableNetworkRequest = struct {
    builder_id: u64,
    enable: bool,
};

pub const ConfigBuilderAddPortForwardRequest = struct {
    builder_id: u64,
    host_port: u16,
    sandbox_port: u16,
};

pub const ConfigBuilderBuildRequest = struct {
    builder_id: u64,
};
pub const ConfigBuilderBuildResponse = struct {
    config_id: u64, // 服务端生成的config唯一ID
    config: zbox.Config, // 返回完整的config结构，方便客户端校验
};

pub const ConfigBuilderDeinitRequest = struct {
    builder_id: u64,
};

// ================================
// Sandbox 相关请求/响应
// ================================
pub const SandboxInitRequest = struct {
    config_id: u64,
    child_args: []const []const u8 = &.{},
};
pub const SandboxInitResponse = struct {
    sandbox_id: u64, // 服务端生成的sandbox唯一ID
};

pub const SandboxSetStrictErrorsRequest = struct {
    sandbox_id: u64,
    enable: bool,
};

pub const SandboxSetIoFdRequest = struct {
    sandbox_id: u64,
    fd: std.posix.fd_t,
};

pub const SandboxSpawnRequest = struct {
    sandbox_id: u64,
};

pub const SandboxWaitRequest = struct {
    sandbox_id: u64,
};
pub const SandboxWaitResponse = struct {
    result: zbox.WaitResult,
};

pub const SandboxDeinitRequest = struct {
    sandbox_id: u64,
};

// 序列化工具函数
pub fn serialize(allocator: std.mem.Allocator, value: anytype) ![]const u8 {
    return std.json.stringifyAlloc(allocator, value, .{});
}

pub fn deserialize(allocator: std.mem.Allocator, comptime T: type, data: []const u8) !T {
    return std.json.parseFromSlice(T, allocator, data, .{});
}