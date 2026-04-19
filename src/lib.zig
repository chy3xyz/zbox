//! zbox - Minimal rootless Linux sandbox library
//! 适用于嵌入到其他Zig项目，如knot3bot

const std = @import("std");

/// 库版本号
pub const version = std.SemanticVersion.parse("0.1.0") catch unreachable;

// 导出公共API
pub const sandbox = @import("sandbox/mod.zig");
pub const Sandbox = sandbox.Sandbox;
pub const WaitResult = sandbox.WaitResult;
pub const decode_wait_status = sandbox.decode_wait_status;

pub const config = @import("config.zig");
pub const Config = config.Config;
pub const PortForward = config.PortForward;
pub const PortForward = config.PortForward;
pub const ConfigBuilder = config.Builder;
pub const load_config = config.load;

// 暴露子模块供高级用户使用
pub const cgroup = @import("cgroup.zig");
pub const network = @import("network/mod.zig");
pub const fs = @import("fs/mod.zig");
pub const seccomp = @import("seccomp.zig");

test {
    // 运行所有子模块测试
    std.testing.refAllDecls(@This());
}
