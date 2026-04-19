const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 暴露模块给依赖项目
    const zbox_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
    });
    b.modules.put(b.dupe("zbox"), zbox_mod) catch @panic("OOM");

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
