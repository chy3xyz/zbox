//! 连接池实现，支持多线程并发访问
const std = @import("std");
const utils = @import("utils.zig");

const Connection = struct {
    sock: std.posix.socket_t,
    last_used: u64,
};

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    max_size: usize,
    connections: std.ArrayList(Connection),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,

    pub fn init(allocator: std.mem.Allocator, socket_path: []const u8, max_size: usize) !*ConnectionPool {
        const self = try allocator.create(ConnectionPool);
        self.* = .{
            .allocator = allocator,
            .socket_path = try allocator.dupe(u8, socket_path),
            .max_size = max_size,
            .connections = std.ArrayList(Connection).init(allocator),
            .mutex = .{},
            .cond = .{},
        };
        return self;
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |conn| {
            std.posix.close(conn.sock);
        }
        self.connections.deinit();
        self.allocator.free(self.socket_path);
        self.allocator.destroy(self);
    }

    // 获取一个连接，如果没有可用连接则创建新的，达到最大数量则阻塞等待
    pub fn acquire(self: *ConnectionPool) !std.posix.socket_t {
        self.mutex.lock();
        defer self.mutex.unlock();

        // 先尝试从池里取可用连接
        while (true) {
            if (self.connections.popOrNull()) |conn| {
                // 简单测试连接是否还活着
                var buf: [1]u8 = undefined;
                const res = std.posix.recv(conn.sock, &buf, std.posix.MSG.PEEK | std.posix.MSG_DONTWAIT);
                if (res == 0) {
                    // 连接已关闭，关闭并继续找下一个
                    std.posix.close(conn.sock);
                    continue;
                }
                return conn.sock;
            }

            // 没有可用连接，检查是否可以创建新连接
            if (self.connections.items.len < self.max_size) {
                // 创建新连接
                const sock = try utils.connectUnixSocket(self.allocator, self.socket_path);
                return sock;
            }

            // 达到最大连接数，等待有连接被释放
            self.cond.wait(&self.mutex);
        }
    }

    // 释放连接回池
    pub fn release(self: *ConnectionPool, sock: std.posix.socket_t) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.connections.items.len < self.max_size) {
            // 回收连接
            self.connections.append(.{
                .sock = sock,
                .last_used = std.time.milliTimestamp(),
            }) catch {
                // 失败则关闭连接
                std.posix.close(sock);
            };
        } else {
            // 池已满，直接关闭
            std.posix.close(sock);
        }

        // 通知等待的线程有可用连接了
        self.cond.signal();
    }
};