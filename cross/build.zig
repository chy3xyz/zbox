const std = @import("std");

pub fn buildCrossClient(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, zbox_module: *std.Build.Module) *std.Build.Module {
    const cross_common = b.createModule(.{
        .root_source_file = b.path("cross/common/common.zig"),
        .imports = &.{
            .{ .name = "zbox", .module = zbox_module },
        },
    });

    const cross_client = b.createModule(.{
        .root_source_file = b.path("cross/client.zig"),
        .imports = &.{
            .{ .name = "zbox", .module = zbox_module },
            .{ .name = "common", .module = cross_common },
        },
    });

    return cross_client;
}

pub fn buildCrossServer(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, zbox_module: *std.Build.Module) *std.Build.Step.Compile {
    const cross_common = b.createModule(.{
        .root_source_file = b.path("cross/common/common.zig"),
        .imports = &.{
            .{ .name = "zbox", .module = zbox_module },
        },
    });

    const server_exe = b.addExecutable(.{
        .name = "zbox-server",
        .root_source_file = b.path("cross/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_exe.root_module.addImport("zbox", zbox_module);
    server_exe.root_module.addImport("common", cross_common);

    b.installArtifact(server_exe);
    return server_exe;
}