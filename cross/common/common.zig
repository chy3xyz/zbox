//! 跨平台适配公共模块

pub const protocol = @import("protocol.zig");
pub const types = @import("types.zig");
pub const utils = @import("utils.zig");

pub usingnamespace protocol;
pub usingnamespace types;
pub usingnamespace utils;
pub const pool = @import("pool.zig");
pub const mempool = @import("mempool.zig");

pub usingnamespace pool;
pub usingnamespace mempool;