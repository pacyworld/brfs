//! peer.zig — one mesh peer connection.
//!
//! Deliberately kqueue-agnostic: the daemon core owns the event loop and
//! calls readReady/writeReady when the fd fires.  This object owns the
//! frame buffers, the HELLO handshake state, and reconnect backoff.
//!
//! Mesh dedup: full mesh with both sides dialing yields two connections
//! per pair.  Deterministic rule: the node with the lexicographically
//! larger node_id keeps its OUTBOUND connection and drops the inbound
//! duplicate; both sides compute the same outcome.
//!
//! Backpressure: a peer that stops reading fills wbuf; past wbuf_cap the
//! connection is dropped (stale peer) — catch-up after reconnect comes
//! from RESYNC, so nothing is lost.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const protocol = @import("protocol.zig");
const contentset = @import("contentset.zig");
const tls = @import("tls.zig");

pub const wbuf_cap: usize = 64 * 1024 * 1024;
pub const rbuf_cap: usize = protocol.max_frame + 4 + 4096;

pub const backoff_initial_ms: i64 = 1_000;
pub const backoff_max_ms: i64 = 30_000;

/// TLS write bounce-buffer size (writeReady).  64KB matches the read-side
/// drain buffer; large enough to keep syscall count low on 1MiB frames.
pub const tls_scratch_size: usize = 64 * 1024;

pub const State = enum {
    connecting, // outbound, non-blocking connect in flight
    tls_handshake, // TCP connected; TLS handshake in progress
    handshake, // TLS done (or no TLS); HELLO sent, peer HELLO pending
    ready,
    closed,
};

/// A MOVE_FROM received from this peer, awaiting its MOVE_TO (they share
/// the sender's rename cookie).  Unpaired past the deadline = the file
/// moved out of the tree on the sender (delete).
pub const RemoteMove = struct {
    path: []u8, // owned
    ver: contentset.Version,
    is_dir: bool,
    deadline_ms: i64,
};

pub const remote_move_timeout_ms: i64 = 2_000;

pub const Peer = struct {
    alloc: Allocator,
    fd: posix.fd_t = -1,
    state: State = .closed,
    outbound: bool = false,
    node_id: ?[]u8 = null, // learned from HELLO (owned)
    /// Outbound only: the node_id this address belongs to, remembered
    /// across disconnects.  The daemon suppresses re-dials while a ready
    /// conn to that node exists (mesh dedup is per-PAIR, not per-conn:
    /// without this the dropped redundant conn redials forever).
    known_id: ?[]u8 = null,
    addr: ?std.net.Address = null, // dial target for outbound peers
    rbuf: std.ArrayList(u8) = .empty,
    wbuf: std.ArrayList(u8) = .empty,
    violations: u32 = 0, // path-validation strikes; demote threshold
    next_retry_ms: i64 = 0,
    backoff_ms: i64 = backoff_initial_ms,
    moves: std.AutoHashMap(u32, RemoteMove), // cookie -> pending MOVE_FROM
    /// TLS connection state (null when TLS not configured or not yet started).
    tls_conn: ?tls.TlsConn = null,
    /// Stable bounce buffer for TLS writes (see writeReady).  Empty until
    /// first use; allocated once, never reallocated.
    tls_scratch: []u8 = &.{},

    pub fn init(alloc: Allocator) Peer {
        return .{ .alloc = alloc, .moves = std.AutoHashMap(u32, RemoteMove).init(alloc) };
    }

    pub fn deinit(self: *Peer) void {
        self.closeFd();
        self.rbuf.deinit(self.alloc);
        self.wbuf.deinit(self.alloc);
        var mit = self.moves.iterator();
        while (mit.next()) |e| self.alloc.free(e.value_ptr.path);
        self.moves.deinit();
        if (self.node_id) |n| self.alloc.free(n);
        if (self.known_id) |n| self.alloc.free(n);
        if (self.tls_conn) |*tc| tc.deinit();
        if (self.tls_scratch.len > 0) self.alloc.free(self.tls_scratch);
    }

    pub fn noteRemoteMove(self: *Peer, cookie: u32, path: []const u8, ver: contentset.Version, is_dir: bool, now_ms: i64) !void {
        if (self.moves.fetchRemove(cookie)) |old| self.alloc.free(old.value.path);
        const owned = try self.alloc.dupe(u8, path);
        try self.moves.put(cookie, .{
            .path = owned,
            .ver = ver,
            .is_dir = is_dir,
            .deadline_ms = now_ms + remote_move_timeout_ms,
        });
    }

    pub fn takeRemoteMove(self: *Peer, cookie: u32) ?RemoteMove {
        const kv = self.moves.fetchRemove(cookie) orelse return null;
        return kv.value; // caller owns path
    }

    /// Expired unpaired MOVE_FROMs (moved out of tree).  Caller frees
    /// each returned path with freeMove.
    pub fn sweepRemoteMoves(self: *Peer, now_ms: i64, out: *std.ArrayList(RemoteMove)) !void {
        var expired: std.ArrayList(u32) = .empty;
        defer expired.deinit(self.alloc);
        var it = self.moves.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.deadline_ms <= now_ms)
                try expired.append(self.alloc, e.key_ptr.*);
        }
        for (expired.items) |cookie| {
            const kv = self.moves.fetchRemove(cookie).?;
            try out.append(self.alloc, kv.value);
        }
    }

    pub fn freeMove(self: *Peer, m: *RemoteMove) void {
        self.alloc.free(m.path);
    }

    pub fn closeFd(self: *Peer) void {
        if (self.tls_conn) |*tc| {
            tc.shutdown();
            tc.deinit();
            self.tls_conn = null;
        }
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
        self.state = .closed;
    }

    /// Mark the connection dead and arm the retry timer (outbound only;
    /// inbound peers are forgotten and re-accepted when they dial).
    pub fn disconnected(self: *Peer, now_ms: i64) void {
        self.closeFd();
        self.rbuf.clearRetainingCapacity();
        self.wbuf.clearRetainingCapacity();
        var mit = self.moves.iterator();
        while (mit.next()) |e| self.alloc.free(e.value_ptr.path);
        self.moves.clearRetainingCapacity();
        if (self.node_id) |n| {
            self.alloc.free(n);
            self.node_id = null;
        }
        if (self.outbound) {
            self.next_retry_ms = now_ms + self.backoff_ms;
            self.backoff_ms = @min(self.backoff_ms * 2, backoff_max_ms);
        }
    }

    /// Begin a non-blocking outbound dial.  Returns the fd to register
    /// (EVFILT_WRITE for connect completion, EVFILT_READ|EV_CLEAR).
    pub fn dial(self: *Peer, addr: std.net.Address) !posix.fd_t {
        const fd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(fd);
        // std.c.connect directly: std.posix.connect's error mapping prints
        // "unexpected errno" noise for immediate failures (ECONNREFUSED on
        // a peer that isn't up yet is NORMAL during mesh startup).
        if (std.c.connect(fd, &addr.any, addr.getOsSockLen()) != 0) {
            const e = std.c._errno().*;
            if (e != @intFromEnum(std.c.E.INPROGRESS) and e != @intFromEnum(std.c.E.AGAIN))
                return error.ConnectFailed; // retried via backoff
        }
        self.fd = fd;
        self.addr = addr;
        self.outbound = true;
        self.state = .connecting;
        return fd;
    }

    /// Adopt an accepted inbound connection.
    pub fn adopt(self: *Peer, fd: posix.fd_t) void {
        self.fd = fd;
        self.outbound = false;
        self.state = .handshake;
    }

    /// Start TLS on an already-connected socket.  Transitions to
    /// .tls_handshake state.  The daemon calls tlsHandshake() when the
    /// socket becomes readable/writable.
    pub fn startTls(self: *Peer, ctx: tls.TlsContext) !void {
        self.tls_conn = if (self.outbound)
            try tls.TlsConn.initClient(ctx, self.fd)
        else
            try tls.TlsConn.initServer(ctx, self.fd);
        self.state = .tls_handshake;
    }

    /// Continue the TLS handshake.  Returns the result so the daemon can
    /// re-arm the appropriate kqueue filter.  On .complete, transitions
    /// to .handshake (ready for HELLO exchange).
    pub fn tlsHandshake(self: *Peer) !tls.HandshakeResult {
        var tc = &(self.tls_conn orelse return error.NoTlsConn);
        const result = tc.doHandshake() catch |err| switch (err) {
            tls.TlsError.HandshakeFailed => return error.TlsHandshakeFailed,
            else => return error.TlsHandshakeFailed,
        };
        if (result == .complete) {
            self.state = .handshake;
            self.backoff_ms = backoff_initial_ms;
        }
        return result;
    }

    /// EVFILT_WRITE fired on a connecting socket: check SO_ERROR.
    /// Returns true when the connect completed.  The daemon will then
    /// call startTls() if TLS is configured, else proceed to HELLO.
    pub fn connectResult(self: *Peer) !bool {
        var err: c_int = 0;
        var len: posix.socklen_t = @sizeOf(c_int);
        if (std.c.getsockopt(self.fd, posix.SOL.SOCKET, posix.SO.ERROR, &err, &len) != 0)
            return error.SocketError;
        if (err != 0) return error.ConnectFailed;
        // State transition decided by the daemon (TLS vs no-TLS).
        self.state = .handshake;
        self.backoff_ms = backoff_initial_ms;
        return true;
    }

    /// Queue a frame for sending.  error.PeerSaturated = drop the conn.
    pub fn send(self: *Peer, msg: protocol.Message) !void {
        const frame = try protocol.encode(self.alloc, msg);
        defer self.alloc.free(frame);
        try self.sendRaw(frame);
    }

    pub fn sendRaw(self: *Peer, frame: []const u8) !void {
        if (self.wbuf.items.len + frame.len > wbuf_cap)
            return error.PeerSaturated;
        try self.wbuf.appendSlice(self.alloc, frame);
    }

    pub fn wantsWrite(self: *const Peer) bool {
        return self.state != .closed and self.wbuf.items.len > 0;
    }

    /// Drain the outbound buffer (called on EVFILT_WRITE).
    /// When TLS is active, uses SSL_write (KTLS makes this a kernel op).
    ///
    /// TLS writes go through a per-peer scratch buffer that is allocated
    /// once and never moves: after a WANT_WRITE mid-burst, OpenSSL's KTLS
    /// path retains the caller's buffer pointer internally, so a retry
    /// after a wbuf realloc (append -> grow -> huge munmap) made the
    /// kernel read unmapped pages — write failed with EFAULT, conn dropped
    /// (rig-proven 2026-08-29, only under link delay/backpressure; LAN
    /// never backpressured so the retained pointer never went stale).
    /// Retrying with an IDENTICAL pointer+len is the strict pre-3.2
    /// SSL_write contract and satisfies KTLS unconditionally.
    pub fn writeReady(self: *Peer) !void {
        while (self.wbuf.items.len > 0) {
            if (self.tls_conn) |*tc| {
                if (self.tls_scratch.len == 0)
                    self.tls_scratch = try self.alloc.alloc(u8, tls_scratch_size);
                const n_req = @min(self.wbuf.items.len, self.tls_scratch.len);
                @memcpy(self.tls_scratch[0..n_req], self.wbuf.items[0..n_req]);
                const result = tc.write(self.tls_scratch[0..n_req]) catch
                    return error.PeerGone;
                switch (result) {
                    .ok => |n| {
                        if (n == 0) return error.PeerGone;
                        self.wbuf.replaceRange(self.alloc, 0, n, &.{}) catch |err| switch (err) {
                            error.OutOfMemory => return err,
                        };
                    },
                    .want_read, .want_write => return,
                }
            } else {
                const n = posix.write(self.fd, self.wbuf.items) catch |err| switch (err) {
                    error.WouldBlock => return,
                    else => return err,
                };
                if (n == 0) return error.PeerGone;
                self.wbuf.replaceRange(self.alloc, 0, n, &.{}) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                };
            }
        }
    }

    /// Pull available bytes into rbuf (called on EVFILT_READ with EV_CLEAR:
    /// drain until WouldBlock).
    /// When TLS is active, uses SSL_read (KTLS makes this a kernel op).
    pub fn readReady(self: *Peer) !void {
        var tmp: [65536]u8 = undefined;
        while (true) {
            if (self.tls_conn) |*tc| {
                const result = tc.read(&tmp) catch |err| switch (err) {
                    tls.TlsError.ConnectionClosed => return error.PeerGone,
                    else => return error.PeerGone,
                };
                switch (result) {
                    .ok => |n| {
                        if (n == 0) return error.PeerGone;
                        if (self.rbuf.items.len + n > rbuf_cap) return error.PeerSaturated;
                        try self.rbuf.appendSlice(self.alloc, tmp[0..n]);
                    },
                    .want_read, .want_write => return,
                }
            } else {
                const n = posix.read(self.fd, &tmp) catch |err| switch (err) {
                    error.WouldBlock => return,
                    else => return err,
                };
                if (n == 0) return error.PeerGone;
                if (self.rbuf.items.len + n > rbuf_cap) return error.PeerSaturated;
                try self.rbuf.appendSlice(self.alloc, tmp[0..n]);
            }
        }
    }

    /// Pop one complete frame (owned copy; caller frees).  null = need
    /// more bytes.  error on protocol garbage = drop the peer.
    pub fn popFrame(self: *Peer) !?[]u8 {
        const total = protocol.frameReady(self.rbuf.items) catch |err| {
            self.violations += 1;
            return err;
        };
        if (total == 0) return null;
        const frame = try self.alloc.dupe(u8, self.rbuf.items[0..total]);
        try self.rbuf.replaceRange(self.alloc, 0, total, &.{});
        return frame;
    }

    /// Validate a received HELLO against our identity and PSK.
    pub fn checkHello(self: *Peer, h: protocol.Hello, our_id: []const u8, our_psk: []const u8) !void {
        if (h.proto != protocol.protocol_version) return error.BadProtocol;
        if (h.node_id.len == 0 or h.node_id.len > 64) return error.BadNodeId;
        if (std.mem.eql(u8, h.node_id, our_id)) return error.SelfPeer;
        if (!timingSafeEql(h.psk, our_psk)) return error.BadPsk;
        if (self.node_id) |n| self.alloc.free(n);
        self.node_id = try self.alloc.dupe(u8, h.node_id);
        if (self.outbound) {
            if (self.known_id) |n| self.alloc.free(n);
            self.known_id = try self.alloc.dupe(u8, h.node_id);
        }
        self.state = .ready;
        self.violations = 0;
    }
};

/// Length-safe constant-time PSK comparison (hashes compared to avoid
/// leaking length via early exit).
fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    var ha: [32]u8 = undefined;
    var hb: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(a, &ha, .{});
    std.crypto.hash.sha2.Sha256.hash(b, &hb, .{});
    return std.crypto.timing_safe.eql([32]u8, ha, hb);
}

/// Monotonic clock in milliseconds (all journal/backoff/debounce math).
pub fn nowMs() i64 {
    const ts = posix.clock_gettime(.MONOTONIC) catch return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

// ---- tests ----

const t = std.testing;

fn socketPair() ![2]posix.fd_t {
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0, &fds) != 0)
        return error.SocketpairFailed;
    return .{ fds[0], fds[1] };
}

fn pump(a: *Peer, b: *Peer) !void {
    // Non-blocking fds, small buffers: one ordered pass each way.
    try a.writeReady();
    try b.writeReady();
    try a.readReady();
    try b.readReady();
}

test "loopback frame exchange via peer buffers" {
    const fds = try socketPair();
    var pa = Peer.init(t.allocator);
    defer pa.deinit();
    var pb = Peer.init(t.allocator);
    defer pb.deinit();
    pa.adopt(fds[0]);
    pb.adopt(fds[1]);

    try pa.send(.{ .fetch_req = .{ .ver = .{ .origin = 1, .seq = 2 }, .offset = 0, .len = 64, .path = "a/b.txt" } });
    try pa.send(.{ .nack = .{ .ver = .{ .origin = 1, .seq = 3 }, .code = 9, .path = "c" } });
    try pump(&pa, &pb);

    const f1 = (try pb.popFrame()).?;
    defer t.allocator.free(f1);
    const m1 = try protocol.decode(f1[4..]);
    try t.expectEqualStrings("a/b.txt", m1.fetch_req.path);

    const f2 = (try pb.popFrame()).?;
    defer t.allocator.free(f2);
    const m2 = try protocol.decode(f2[4..]);
    try t.expectEqual(@as(u16, 9), m2.nack.code);

    try t.expectEqual(@as(?[]u8, null), try pb.popFrame());
}

test "fragmented delivery reassembles" {
    const fds = try socketPair();
    var pa = Peer.init(t.allocator);
    defer pa.deinit();
    var pb = Peer.init(t.allocator);
    defer pb.deinit();
    pa.adopt(fds[0]);
    pb.adopt(fds[1]);

    // Byte-at-a-time writes exercise the partial-frame path.
    const frame = try protocol.encode(t.allocator, .{ .tombstone = .{ .ver = .{ .origin = 5, .seq = 6 }, .is_dir = false, .path = "gone" } });
    defer t.allocator.free(frame);
    try pa.wbuf.appendSlice(t.allocator, frame);
    for (0..frame.len) |i| {
        const n = try posix.write(fds[0], frame[i .. i + 1]);
        try t.expectEqual(@as(usize, 1), n);
        try pb.readReady();
        if (i + 1 < frame.len)
            try t.expectEqual(@as(?[]u8, null), try pb.popFrame());
    }
    const f = (try pb.popFrame()).?;
    defer t.allocator.free(f);
    const m = try protocol.decode(f[4..]);
    try t.expectEqualStrings("gone", m.tombstone.path);
}

test "hello validation: psk, self, version" {
    var p = Peer.init(t.allocator);
    defer p.deinit();
    var nonce: [protocol.nonce_len]u8 = undefined;
    @memset(&nonce, 1);
    const base = protocol.Hello{ .proto = protocol.protocol_version, .node_id = "peer-b", .psk = "right", .nonce = nonce };

    try p.checkHello(base, "us", "right");
    try t.expect(p.state == .ready);
    try t.expectEqualStrings("peer-b", p.node_id.?);

    var q = Peer.init(t.allocator);
    defer q.deinit();
    try t.expectError(error.BadPsk, q.checkHello(base, "us", "wrong"));
    try t.expectError(error.SelfPeer, q.checkHello(base, "peer-b", "right"));
    var old = base;
    old.proto = 99;
    try t.expectError(error.BadProtocol, q.checkHello(old, "us", "right"));
}

test "wbuf cap saturates" {
    var p = Peer.init(t.allocator);
    defer p.deinit();
    p.state = .ready;
    const big = try t.allocator.alloc(u8, wbuf_cap);
    defer t.allocator.free(big);
    @memset(big, 0);
    try p.sendRaw(big[0..1000]);
    // Force wbuf near cap without 64MB of test churn: simulate full buffer.
    try p.wbuf.resize(t.allocator, wbuf_cap);
    try t.expectError(error.PeerSaturated, p.sendRaw("x"));
}

test "backoff schedule" {
    var p = Peer.init(t.allocator);
    defer p.deinit();
    p.outbound = true;
    p.disconnected(10_000);
    try t.expectEqual(@as(i64, 11_000), p.next_retry_ms);
    try t.expectEqual(@as(i64, 2_000), p.backoff_ms);
    p.disconnected(20_000);
    try t.expectEqual(@as(i64, 22_000), p.next_retry_ms);
    p.backoff_ms = backoff_max_ms;
    p.disconnected(50_000);
    try t.expectEqual(@as(i64, 50_000 + backoff_max_ms), p.next_retry_ms);
}
