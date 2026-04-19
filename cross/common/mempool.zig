//! 通用内存池，减少频繁分配释放开销
const std = @import("std");

pub fn ObjectPool(comptime T: type, comptime max_size: usize) type {
    return struct {
        allocator: std.mem.Allocator,
        pool: std.ArrayList(*T),
        mutex: std.Thread.Mutex,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .pool = std.ArrayList(*T).init(allocator),
                .mutex = .{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.pool.items) |obj| {
                self.allocator.destroy(obj);
            }
            self.pool.deinit();
        }

        pub fn acquire(self: *Self) !*T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.pool.popOrNull()) |obj| {
                return obj;
            }

            // 没有可用对象，创建新的
            return try self.allocator.create(T);
        }

        pub fn release(self: *Self, obj: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // 重置对象内容
            @memset(std.mem.asBytes(obj), 0);

            if (self.pool.items.len < max_size) {
                self.pool.append(obj) catch {
                    self.allocator.destroy(obj);
                };
            } else {
                self.allocator.destroy(obj);
            }
        }
    };
}

// 通用缓冲区池，用于临时IO/序列化缓冲区
pub const BufferPool = struct {
    allocator: std.mem.Allocator,
    buffer_size: usize,
    max_count: usize,
    pool: std.ArrayList([]u8),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize, max_count: usize) BufferPool {
        return .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .max_count = max_count,
            .pool = std.ArrayList([]u8).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.pool.items) |buf| {
            self.allocator.free(buf);
        }
        self.pool.deinit();
    }

    pub fn acquire(self: *BufferPool) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pool.popOrNull()) |buf| {
            return buf;
        }

        // 没有可用缓冲区，创建新的
        return try self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        // 校验缓冲区大小是否匹配
        if (buf.len != self.buffer_size) {
            self.allocator.free(buf);
            return;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pool.items.len < self.max_count) {
            self.pool.append(buf) catch {
                self.allocator.free(buf);
            };
        } else {
            self.allocator.free(buf);
        }
    }
};