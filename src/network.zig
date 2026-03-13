//! Loopback interface setup for sandboxed network namespaces.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const NetworkError = error{
    GetFlagsFailed,
    SetFlagsFailed,
    VerifyFailed,
};

/// Bring up the `lo` interface so sandboxed processes can reach localhost.
///
/// Only sets `IFF.UP`; `RUNNING` is kernel-managed and will assert itself
/// once the interface is active.
pub fn bring_up_loopback() NetworkError!void {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch
        return error.GetFlagsFailed;
    defer posix.close(fd);

    var ifr = std.mem.zeroInit(posix.ifreq, .{});
    const if_name = "lo";
    comptime std.debug.assert(if_name.len < linux.IFNAMESIZE);
    @memcpy(ifr.ifrn.name[0..if_name.len], if_name);

    if (posix.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS)
        return error.GetFlagsFailed;

    var flags: linux.IFF = ifr.ifru.flags;
    flags.UP = true;
    ifr.ifru.flags = flags;

    if (posix.errno(linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS)
        return error.SetFlagsFailed;

    // Postcondition: re-read and verify UP is set.
    if (posix.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS)
        return error.VerifyFailed;
    std.debug.assert(ifr.ifru.flags.UP);
}
