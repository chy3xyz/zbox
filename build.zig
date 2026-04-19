const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 跨平台支持编译选项
    const enable_cross = b.option(bool, "enable-cross", "Enable cross-platform support (Windows/macOS)") orelse false;

    // 暴露模块给依赖项目
    const zbox_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
    });
    b.modules.put(b.dupe("zbox"), zbox_mod) catch @panic("OOM");

    // 编译跨平台模块（如果开启）
    if (enable_cross) {
        const cross_build = @import("cross/build.zig");
        const cross_client_mod = cross_build.buildCrossClient(b, target, optimize, zbox_mod);
        b.modules.put(b.dupe("zbox-client"), cross_client_mod) catch @panic("OOM");
        
        // 只有Linux目标编译zbox-server
        if (target.result.os.tag == .linux) {
            _ = cross_build.buildCrossServer(b, target, optimize, zbox_mod);
        }
    }
    // 构建CLI可执行文件
    const exe = b.addExecutable(.{
        .name = "zbox",
        .target = target,
        .optimize = optimize,
    });
    exe.setRootSourceFile(b.path("src/main.zig"));
    exe.addModule("zbox", zbox_mod);
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // 测试构建目标
    const tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
