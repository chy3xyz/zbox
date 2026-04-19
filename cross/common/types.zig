const std = @import("std");

// 跨平台错误码
pub const CrossError = error{
    // 环境相关错误
    VmNotInstalled,
    VmInstallFailed,
    VmStartFailed,
    VmConnectionFailed,
    VmTimeout,

    // 协议相关错误
    InvalidRequest,
    InvalidResponse,
    SerializeFailed,
    DeserializeFailed,

    // 路径相关错误
    InvalidPath,
    PathConvertFailed,

    // API相关错误
    BuilderNotFound,
    ConfigNotFound,
    SandboxNotFound,
    CallbackFailed,
};

// 虚拟机类型
pub const VmType = enum {
    wsl2, // Windows WSL2
    lima, // macOS Lima
    native, // Linux原生
};

// 虚拟机配置
pub const VmConfig = struct {
    vm_type: VmType,
    name: []const u8,
    cpu_cores: u32 = 2,
    memory_mb: u32 = 512,
    shared_dirs: []const []const u8 = &.{},
    port_forwards: []const struct { host: u16, guest: u16 } = &.{},
};

// 沙箱运行环境信息
pub const SandboxEnv = struct {
    os: std.Target.Os.Tag,
    arch: std.Target.Cpu.Arch,
    zbox_version: []const u8,
    vm_type: VmType,
};