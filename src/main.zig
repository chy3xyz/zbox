//! Entry point for zbox CLI tool
const std = @import("std");
const zbox = @import("zbox");
const args = @import("args.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var parsed_args = args.parse(allocator, init.minimal.args);

    var box = try zbox.Sandbox.init(allocator, parsed_args);
    defer box.deinit();

    try box.spawn();
    try box.wait();
}
