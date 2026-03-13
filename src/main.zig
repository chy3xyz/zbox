//! Entry point for zbox — parses CLI arguments and runs the sandbox.
const std = @import("std");
const config = @import("config.zig");
const sandbox = @import("sandbox.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var cfg = try parse_args(allocator);
    errdefer cfg.deinit(allocator);

    var box = try sandbox.Sandbox.init(allocator, cfg);
    defer box.deinit();

    try box.spawn();
    try box.wait();
}

fn print_help() void {
    std.debug.print(
        \\zbox - Minimal Linux namespace sandbox
        \\
        \\Usage: zbox [options]
        \\
        \\Options:
        \\  -b, --binary <path>   Target binary (default: /bin/busybox)
        \\  -r, --root <path>     Container root (default: auto-generated)
        \\  -h, --help            Show this help
        \\  --                    Forward remaining args to sandboxed binary
        \\
        \\Examples:
        \\  zbox                       # busybox sh in sandbox
        \\  zbox -b /bin/busybox -- ls # run ls inside sandbox
        \\
    , .{});
}

fn parse_args(allocator: std.mem.Allocator) !config.Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cfg = config.Config.init();
    errdefer cfg.deinit(allocator);

    var i: u32 = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < args.len) : (i += 1) {
                if (cfg.args_count >= config.args_max) {
                    std.debug.print("error: too many arguments (max {d})\n", .{config.args_max});
                    std.process.exit(1);
                }
                cfg.args[cfg.args_count] = try allocator.dupeZ(u8, args[i]);
                cfg.args_count += 1;
            }
            break;
        }

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            print_help();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--binary")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: {s} requires an argument\n", .{arg});
                std.process.exit(1);
            }
            if (cfg.owns_binary) allocator.free(cfg.binary);
            cfg.binary = try allocator.dupeZ(u8, args[i]);
            cfg.owns_binary = true;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--root")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("error: {s} requires an argument\n", .{arg});
                std.process.exit(1);
            }
            if (cfg.owns_root) {
                if (cfg.root) |r| allocator.free(r);
            }
            cfg.root = try allocator.dupe(u8, args[i]);
            cfg.owns_root = true;
        } else {
            std.debug.print("error: unknown argument: {s}\n", .{arg});
            print_help();
            std.process.exit(1);
        }
    }

    // The binary must be an absolute path for chroot to work.
    std.debug.assert(cfg.binary.len > 0 and cfg.binary[0] == '/');

    return cfg;
}
