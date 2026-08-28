//! ctl.zig — the /var/run/brfsd.sock operator control channel.
//!
//! Text protocol: one line per request, response = text until EOF (the
//! daemon answers then closes).  Debuggable with nc -U / socat; no codec
//! to mutation-test.  The socket is 0600 (brfsd runs as root in POC): the
//! control plane triggers resyncs and moves files (conflicts restore), so
//! it stays root-only.
//!
//! The daemon side handles requests on the core kqueue loop (never a
//! thread): responses are small and local, capped at max_response.

const std = @import("std");
const posix = std.posix;

pub const sock_path = "/var/run/brfsd.sock";
pub const max_request = 4096;
/// Responses truncate past this with a marker line (operator tool, not a
/// data channel — a 10k-entry conflicts list belongs in the filesystem).
pub const max_response = 16 * 1024;

pub const Command = union(enum) {
    status,
    peers,
    backlog,
    journal,
    /// Full resync: RESYNC_REQ to every ready peer + local rescan floor.
    resync,
    conflicts_list,
    /// Restore a conflicts/ entry into the tree (joins as fresh local
    /// content — the tap announces it like any local create).
    conflicts_restore: []const u8,
    /// Delete conflicts/ entries (all, or those containing the argument).
    conflicts_prune: ?[]const u8,
    /// Prometheus text exposition of daemon state + per-member vector lag
    /// (the convergence health check).  brfsctl prepends the kernel
    /// counters (security.brfs.* via sysctl).
    metrics,
    /// Mass-delete guard state (gap #17).
    massdelete,
    /// Release the guard latch + schedule a rescan (the suppressed deletes
    /// re-derive as honest tombstones — the operator confirmed intent).
    massdelete_resume,
    unknown,
};

pub fn parseCommand(line: []const u8) Command {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    var it = std.mem.tokenizeScalar(u8, trimmed, ' ');
    const verb = it.next() orelse return .unknown;
    const arg = it.next();

    const eq = std.mem.eql;
    if (eq(u8, verb, "status")) return .status;
    if (eq(u8, verb, "peers")) return .peers;
    if (eq(u8, verb, "backlog")) return .backlog;
    if (eq(u8, verb, "journal")) return .journal;
    if (eq(u8, verb, "resync")) return .resync;
    if (eq(u8, verb, "conflicts")) {
        const sub = arg orelse return .conflicts_list;
        if (eq(u8, sub, "list")) return .conflicts_list;
        if (eq(u8, sub, "restore")) {
            const name = it.next() orelse return .unknown;
            return .{ .conflicts_restore = name };
        }
        if (eq(u8, sub, "prune")) return .{ .conflicts_prune = it.next() };
        return .unknown;
    }
    if (eq(u8, verb, "metrics")) return .metrics;
    if (eq(u8, verb, "massdelete")) {
        const sub = arg orelse return .massdelete;
        if (eq(u8, sub, "resume")) return .massdelete_resume;
        return .unknown;
    }
    return .unknown;
}

extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;

/// Bind a unix stream listener (stale socket unlinked, mode 0600,
/// non-blocking).  Caller registers it on the core kqueue.
pub fn listen(path: []const u8) !posix.fd_t {
    var addr = try std.net.Address.initUnix(path);
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(fd);

    // Stale socket from a previous run: bind would EADDRINUSE.
    std.fs.cwd().deleteFile(path) catch {};

    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    const path_z = try std.posix.toPosixPath(path);
    if (chmod(&path_z, 0o600) != 0) return error.ChmodFailed;
    try posix.listen(fd, 16);
    return fd;
}

/// Accept one pending connection (non-blocking).  error.WouldBlock when
/// the queue is drained (edge-triggered callers loop until this).
pub fn accept(listen_fd: posix.fd_t) !posix.fd_t {
    return posix.accept(listen_fd, null, null, posix.SOCK.NONBLOCK);
}

// ---- tests ----

const t = std.testing;

test "parseCommand matrix" {
    try t.expect(parseCommand("status\n") == .status);
    try t.expect(parseCommand("peers") == .peers);
    try t.expect(parseCommand("backlog") == .backlog);
    try t.expect(parseCommand("journal") == .journal);
    try t.expect(parseCommand("resync") == .resync);
    try t.expect(parseCommand("conflicts") == .conflicts_list);
    try t.expect(parseCommand("conflicts list") == .conflicts_list);
    try t.expect(parseCommand("  conflicts   prune \t\r\n") == .conflicts_prune);
    const prune = parseCommand("conflicts prune big.bin");
    try t.expect(prune == .conflicts_prune);
    try t.expectEqualStrings("big.bin", prune.conflicts_prune.?);
    const restore = parseCommand("conflicts restore sub/file.txt.12345");
    try t.expect(restore == .conflicts_restore);
    try t.expectEqualStrings("sub/file.txt.12345", restore.conflicts_restore);
    try t.expect(parseCommand("conflicts restore") == .unknown);
    try t.expect(parseCommand("metrics") == .metrics);
    try t.expect(parseCommand("massdelete") == .massdelete);
    try t.expect(parseCommand("massdelete resume") == .massdelete_resume);
    try t.expect(parseCommand("massdelete bogus") == .unknown);
    try t.expect(parseCommand("bogus") == .unknown);
    try t.expect(parseCommand("") == .unknown);
    try t.expect(parseCommand("conflicts bogus") == .unknown);
}

test "unix listener roundtrip" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const alloc = t.allocator;
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const sp = try std.fs.path.join(alloc, &.{ base, "test.sock" });
    defer alloc.free(sp);

    const lfd = try listen(sp);
    defer posix.close(lfd);

    // Client connects + sends a one-line request (blocking CLI side).
    var addr = try std.net.Address.initUnix(sp);
    const cfd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    defer posix.close(cfd);
    try posix.connect(cfd, &addr.any, addr.getOsSockLen());
    _ = try posix.write(cfd, "status\n");

    const afd = try accept(lfd);
    defer posix.close(afd);
    var buf: [max_request]u8 = undefined;
    const n = try posix.read(afd, &buf);
    try t.expect(n > 0);
    try t.expect(parseCommand(buf[0..n]) == .status);

    // Queue drained: edge-triggered accept loops until WouldBlock.
    try t.expectError(error.WouldBlock, accept(lfd));

    // Socket is 0600.
    const st = try std.fs.cwd().statFile(sp);
    _ = st;
}
