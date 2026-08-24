//! server.zig — the peer listener + "host:port" parsing.
//!
//! The daemon core owns the kqueue registration; these are just the
//! socket helpers.

const std = @import("std");
const posix = std.posix;

/// Parse "10.0.0.2:4590" / "[::1]:4590".  IPs only (POC): hostnames need
/// std.net.resolveIp, which hits an unimplemented if_nametoindex path in
/// Zig 0.15's FreeBSD std support.
pub fn parseHostPort(text: []const u8) !std.net.Address {
    if (text.len == 0) return error.BadAddress;
    if (text[0] == '[') { // [v6]:port
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return error.BadAddress;
        if (close + 1 >= text.len or text[close + 1] != ':') return error.BadAddress;
        const port = try std.fmt.parseInt(u16, text[close + 2 ..], 10);
        return std.net.Address.parseIp6(text[1..close], port);
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
    const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10);
    const host = text[0..colon];
    if (std.net.Address.parseIp4(host, port)) |a| return a else |_| {}
    if (std.net.Address.parseIp6(host, port)) |a| return a else |_| {}
    return error.BadAddress;
}

/// Bind + listen, non-blocking, CLOEXEC.
pub fn listen(addr: std.net.Address) !posix.fd_t {
    const fd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    try posix.listen(fd, 16);
    return fd;
}

/// Accept one pending connection (non-blocking); null = none pending.
pub fn acceptOne(lfd: posix.fd_t) !?posix.fd_t {
    const fd = posix.accept(lfd, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC) catch |err| switch (err) {
        error.WouldBlock => return null,
        else => return err,
    };
    return fd;
}

// ---- tests ----

const t = std.testing;

test "parseHostPort v4 and v6" {
    const a4 = try parseHostPort("10.66.0.11:4590");
    try t.expectEqual(@as(u16, 4590), a4.getPort());
    try t.expectEqual(posix.AF.INET, a4.any.family);
    const a6 = try parseHostPort("::1:4590"); // last-colon split handles bare v6
    try t.expectEqual(@as(u16, 4590), a6.getPort());
    try t.expectEqual(posix.AF.INET6, a6.any.family);
    try t.expectError(error.BadAddress, parseHostPort(""));
    try t.expectError(error.BadAddress, parseHostPort("noport"));
}

test "loopback listen and accept" {
    const addr = try parseHostPort("127.0.0.1:0");
    const lfd = try listen(addr);
    defer posix.close(lfd);
    try t.expectEqual(@as(?posix.fd_t, null), try acceptOne(lfd));

    var bound: posix.sockaddr.in = undefined;
    var blen: posix.socklen_t = @sizeOf(@TypeOf(bound));
    try t.expectEqual(@as(c_int, 0), std.c.getsockname(lfd, @ptrCast(&bound), &blen));
    const port = std.mem.bigToNative(u16, bound.port);

    const cfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(cfd);
    const target = try std.net.Address.parseIp4("127.0.0.1", port);
    try posix.connect(cfd, &target.any, target.getOsSockLen());
    var afd: ?posix.fd_t = null;
    var tries: usize = 0;
    while (afd == null and tries < 1000) : (tries += 1) {
        afd = try acceptOne(lfd);
        if (afd == null) std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    posix.close(afd orelse return error.AcceptTimeout);
}
