//! daemon.zig — the brfsd core: one kqueue event loop + one drainer thread.
//!
//! Thread model (locked decision 7): the drainer thread owns the ring pop
//! side (blocking read on /dev/brfs, batch push through a mutex-guarded
//! queue, pipe-trick wakeup).  Everything else — journal, content set,
//! peer protocol, installer, resync — runs on the single core thread, so
//! no locking exists anywhere on the replication logic.
//!
//! Event sources: drainer pipe (kernel events), listener (inbound peers),
//! peer conns (EV_CLEAR reads, armed writes), EVFILT_SIGNAL shutdown, and
//! a computed kevent timeout covering journal debounce deadlines, peer
//! reconnect backoff, remote-move expiry, and the ring-seq checkpoint
//! cadence.  No timers, no polling flags (house async rules).

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const config = @import("config.zig");
const events = @import("events.zig");
const contentset = @import("contentset.zig");
const journal = @import("journal.zig");
const protocol = @import("protocol.zig");
const peer_mod = @import("peer.zig");
const server = @import("server.zig");
const installer = @import("installer.zig");
const resync = @import("resync.zig");

const ContentSet = contentset.ContentSet;
const Journal = journal.Journal;
const Peer = peer_mod.Peer;
const Version = contentset.Version;

const c_event = @cImport({
    @cInclude("sys/event.h");
});

const KEvent = c_event.struct_kevent;

extern "c" fn kqueue() c_int;
extern "c" fn kevent(kq: c_int, changelist: ?[*]const KEvent, nchanges: c_int, eventlist: ?[*]KEvent, nevents: c_int, timeout: ?*const std.c.timespec) c_int;
extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) c_int;

const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0x0004;

const checkpoint_interval_ms: i64 = 5_000;
const rescan_cooldown_ms: i64 = 1_000;
const max_violations: u32 = 8;

pub const Level = enum { info, warn, err };

pub fn log(comptime level: Level, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "brfsd[" ++ @tagName(level) ++ "]: " ++ fmt ++ "\n", args) catch return;
    _ = posix.write(2, msg) catch {};
}

fn makeKevent(ident: usize, filter: c_short, flags: c_ushort, udata: ?*anyopaque) KEvent {
    return .{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = 0,
        .data = 0,
        .udata = udata,
        .ext = [_]u64{ 0, 0, 0, 0 },
    };
}

/// Drainer -> core handoff: mutex-guarded batch queue + pipe wakeup.
const EventQueue = struct {
    alloc: Allocator,
    mutex: std.Thread.Mutex = .{},
    items: std.ArrayList(events.Event) = .empty,
    wake_wr: posix.fd_t,

    fn pushBatch(self: *EventQueue, batch: []const events.Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.items.appendSlice(self.alloc, batch) catch return; // drop on OOM; overflow policy is the rescan floor
        // Non-blocking wake: a full pipe means a wakeup is already pending.
        _ = posix.write(self.wake_wr, "x") catch {};
    }

    fn take(self: *EventQueue, out: *std.ArrayList(events.Event)) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        out.appendSlice(self.alloc, self.items.items) catch return;
        self.items.clearRetainingCapacity();
    }
};

/// Thread entry for the ring drainer (spawned by main).
pub fn drainerEntry(dev_fd: posix.fd_t, evq: *EventQueue) void {
    drainerMain(dev_fd, evq);
}

fn drainerMain(dev_fd: posix.fd_t, evq: *EventQueue) void {
    // Blocking read: this thread exists to own the ring pop side.
    const flags = fcntl(dev_fd, F_GETFL, 0);
    _ = fcntl(dev_fd, F_SETFL, flags & ~O_NONBLOCK);
    var buf: [65536]u8 align(@alignOf(events.Event)) = undefined;
    while (true) {
        const n = posix.read(dev_fd, &buf) catch |err| {
            log(.err, "drainer read failed: {s} — exiting drainer", .{@errorName(err)});
            return;
        };
        if (n == 0) continue;
        const count = n / @sizeOf(events.Event);
        const ptr: [*]const events.Event = @ptrCast(@alignCast(&buf));
        evq.pushBatch(ptr[0..count]);
    }
}

/// In-flight incoming fetch metadata (from the ANNOUNCE that started it).
const Incoming = struct {
    ver: Version,
    size: u64,
    sha256: [32]u8,
    mode: u16,
    mtime_sec: i64,
    mtime_nsec: u32,
    deadline_ms: i64,
    retries: u8 = 0,
};

const fetch_timeout_ms: i64 = 30_000;

pub const Daemon = struct {
    alloc: Allocator,
    cfg: *const config.Config,
    psk: []const u8,
    cs: ContentSet,
    jr: Journal,
    inst: installer.Installer,
    dev_fd: posix.fd_t,
    kq: c_int = -1,
    listen_fd: posix.fd_t = -1,
    wake_rd: posix.fd_t = -1,
    evq: EventQueue,
    peers: std.ArrayList(*Peer) = .empty,
    changes: std.ArrayList(KEvent) = .empty, // staged changelist
    batch: std.ArrayList(events.Event) = .empty, // drained kernel events
    incoming: std.StringHashMap(Incoming),
    dead: std.ArrayList(*Peer) = .empty,
    move_cookie: u32 = 0,
    resynced: bool = false,
    need_rescan: bool = false,
    last_rescan_ms: i64 = 0,
    last_checkpoint_ms: i64 = 0,
    running: bool = true,

    pub fn init(alloc: Allocator, cfg: *const config.Config, psk: []const u8, dev_fd: posix.fd_t, wake_rd: posix.fd_t, wake_wr: posix.fd_t) !Daemon {
        var cs = try ContentSet.open(alloc, cfg.state_dir, cfg.node_id);
        errdefer cs.close();
        const inst = try installer.Installer.init(alloc, cfg.replicated_path, cfg.state_dir);
        return .{
            .alloc = alloc,
            .cfg = cfg,
            .psk = psk,
            .cs = cs,
            .jr = Journal.init(alloc, 250),
            .inst = inst,
            .dev_fd = dev_fd,
            .evq = .{ .alloc = alloc, .wake_wr = wake_wr },
            .wake_rd = wake_rd,
            .incoming = std.StringHashMap(Incoming).init(alloc),
        };
    }

    fn stageChange(self: *Daemon, ident: usize, filter: c_short, flags: c_ushort, udata: ?*anyopaque) void {
        self.changes.append(self.alloc, makeKevent(ident, filter, flags, udata)) catch {};
    }

    fn registerPeerFd(self: *Daemon, p: *Peer) void {
        self.stageChange(@intCast(p.fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, p);
        if (p.state == .connecting or p.wantsWrite())
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    fn dropPeer(self: *Daemon, p: *Peer, now_ms: i64, why: []const u8) void {
        if (p.state == .closed) return;
        log(.warn, "peer {s} dropped: {s}", .{ p.node_id orelse "?", why });
        if (p.fd >= 0) {
            self.stageChange(@intCast(p.fd), c_event.EVFILT_READ, c_event.EV_DELETE, null);
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_DELETE, null);
        }
        p.disconnected(now_ms);
        if (!p.outbound) {
            // Inbound peers are ephemeral: remove from the active set and
            // defer destruction to the end of the dispatch round (callers
            // may still hold the pointer until then).
            for (self.peers.items, 0..) |q, i| {
                if (q == p) {
                    _ = self.peers.swapRemove(i);
                    break;
                }
            }
            self.dead.append(self.alloc, p) catch {};
        }
    }

    fn reapDead(self: *Daemon) void {
        for (self.dead.items) |p| {
            var victim = p;
            victim.deinit();
            self.alloc.destroy(victim);
        }
        self.dead.clearRetainingCapacity();
    }

    pub fn run(self: *Daemon) !void {
        const alloc = self.alloc;

        self.kq = kqueue();
        if (self.kq < 0) return error.KqueueFailed;

        var mask = posix.sigemptyset();
        _ = std.c.sigaddset(&mask, 15);
        _ = std.c.sigaddset(&mask, 2);
        _ = std.c.sigprocmask(std.c.SIG.BLOCK, &mask, null);
        self.stageChange(15, c_event.EVFILT_SIGNAL, c_event.EV_ADD, null);
        self.stageChange(2, c_event.EVFILT_SIGNAL, c_event.EV_ADD, null);
        self.stageChange(@intCast(self.wake_rd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, null);

        // Root dir index entry so events under the root resolve.
        const root_st = try installer.statPath(self.cfg.replicated_path);
        try self.cs.indexRoot(@intCast(root_st.dev), @intCast(root_st.ino));

        // Orphaned staging files from a kill -9 (T8) are garbage.
        self.cleanStaging();

        // Listener + outbound dials.
        if (self.cfg.listen.len > 0) {
            const addr = server.parseHostPort(self.cfg.listen) catch {
                log(.err, "bad listen address {s}", .{self.cfg.listen});
                return error.BadAddress;
            };
            self.listen_fd = try server.listen(addr);
            self.stageChange(@intCast(self.listen_fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, null);
            log(.info, "listening on {s}", .{self.cfg.listen});
        }
        for (self.cfg.peers[0..self.cfg.num_peers]) |peer_text| {
            const p = try alloc.create(Peer);
            p.* = Peer.init(alloc);
            p.outbound = true;
            p.addr = server.parseHostPort(peer_text) catch {
                log(.err, "bad peer address {s}", .{peer_text});
                alloc.destroy(p);
                continue;
            };
            p.next_retry_ms = 0; // dial immediately
            try self.peers.append(alloc, p);
        }

        // Startup reconciliation (gap #8): a non-primary with an empty set
        // pulls before announcing; everyone else scans now.
        self.resynced = self.cfg.primary or self.cs.map.count() > 0;
        if (self.resynced) {
            const stats = try resync.scan(alloc, self.cfg.replicated_path, &self.cs, &self.jr, peer_mod.nowMs());
            log(.info, "startup scan: seen={d} new={d} mod={d} del={d} same={d}", .{
                stats.seen, stats.announced_new, stats.announced_modified, stats.announced_deleted, stats.unchanged,
            });
        } else {
            log(.info, "joining as non-primary: suppressing local state until first RESYNC", .{});
        }
        try self.cs.flush();

        var evlist: [16]KEvent = undefined;
        while (self.running) {
            const now = peer_mod.nowMs();
            const timeout_ms = self.nextTimeout(now);
            var ts = std.c.timespec{ .sec = @intCast(@divTrunc(timeout_ms, 1000)), .nsec = @intCast(@rem(timeout_ms, 1000) * 1_000_000) };
            const nchanges: c_int = @intCast(self.changes.items.len);
            const changelist: ?[*]const KEvent = if (nchanges > 0) self.changes.items.ptr else null;
            const nev = kevent(self.kq, changelist, nchanges, &evlist, evlist.len, &ts);
            self.changes.clearRetainingCapacity();
            if (nev < 0) {
                if (std.c._errno().* != 4)
                    log(.err, "kevent failed errno={d}", .{std.c._errno().*});
                continue;
            }

            for (evlist[0..@intCast(nev)]) |*ev| {
                if (ev.filter == c_event.EVFILT_SIGNAL) {
                    log(.info, "signal {d}: shutting down", .{ev.ident});
                    self.running = false;
                } else if (ev.filter == c_event.EVFILT_READ and ev.udata == null and @as(posix.fd_t, @intCast(ev.ident)) == self.wake_rd) {
                    self.onWakePipe();
                } else if (ev.filter == c_event.EVFILT_READ and ev.udata == null and @as(posix.fd_t, @intCast(ev.ident)) == self.listen_fd) {
                    self.onAccept();
                } else if (ev.udata) |ud| {
                    const p: *Peer = @ptrCast(@alignCast(ud));
                    if (ev.filter == c_event.EVFILT_READ) self.onPeerReadable(p);
                    if (ev.filter == c_event.EVFILT_WRITE) self.onPeerWritable(p);
                }
            }

            self.timerPass();
            self.reapDead();
        }

        // Clean shutdown: persist state, release the kernel watch root.
        log(.info, "shutting down: checkpoint + snapshot", .{});
        self.cs.checkpoint(self.jr.high_seq) catch {};
        self.cs.snapshot() catch {};
        events.delRoot(self.dev_fd, self.cfg.replicated_path) catch {};
    }

    fn nextTimeout(self: *Daemon, now: i64) i64 {
        var best: i64 = checkpoint_interval_ms;
        if (self.resynced) {
            if (self.jr.nextDeadlineIn(now)) |d| best = @min(best, @max(d, 0));
        }
        for (self.peers.items) |p| {
            if (p.outbound and p.state == .closed)
                best = @min(best, @max(p.next_retry_ms - now, 0));
            var it = p.moves.iterator();
            while (it.next()) |e|
                best = @min(best, @max(e.value_ptr.deadline_ms - now, 0));
        }
        if (self.need_rescan)
            best = @min(best, @max(self.last_rescan_ms + rescan_cooldown_ms - now, 0));
        return @max(best, 1);
    }

    // ---- kernel event intake ----

    fn onWakePipe(self: *Daemon) void {
        var trash: [256]u8 = undefined;
        while (true) {
            const n = posix.read(self.wake_rd, &trash) catch break;
            if (n == 0) break;
        }
        self.batch.clearRetainingCapacity();
        self.evq.take(&self.batch);
        const now = peer_mod.nowMs();
        for (self.batch.items) |*bev| self.onKernelEvent(bev, now);
    }

    fn onKernelEvent(self: *Daemon, bev: *const events.Event, now: i64) void {
        if (bev.abi != events.abi_version) return;
        const op: events.Op = @enumFromInt(bev.op);
        if (op == .overflow) {
            log(.warn, "ring overflow seq={d}: scheduling tree rescan", .{bev.seq});
            self.need_rescan = true;
            if (bev.seq > self.jr.high_seq) self.jr.high_seq = bev.seq;
            return;
        }
        const name = bev.nameSlice();
        if (name.len == 0) return;
        const dir = self.cs.dirPath(bev.fsid, bev.dir_fileid) orelse {
            // Directory unknown to us (created while down, or index gap):
            // the scan floor recovers it.
            self.need_rescan = true;
            return;
        };
        var pathbuf: [4096]u8 = undefined;
        const rel = if (dir.len == 0)
            std.fmt.bufPrint(&pathbuf, "{s}", .{name}) catch return
        else
            std.fmt.bufPrint(&pathbuf, "{s}/{s}", .{ dir, name }) catch return;

        // Self-echo suppression (rule 6): swallow our own install/rename
        // events, but ONLY if the file still matches what we installed.
        if (self.jr.peekEcho(rel)) |echo| {
            const swallowed = switch (echo.kind) {
                .install => self.verifyInstallEcho(rel, echo),
                .move_from => blk: {
                    const abs = self.inst.absPath(rel) catch break :blk false;
                    defer self.alloc.free(abs);
                    _ = installer.statPath(abs) catch break :blk true; // gone: our rename
                    break :blk false;
                },
            };
            if (swallowed) {
                self.jr.clearEcho(rel);
                if (bev.seq > self.jr.high_seq) self.jr.high_seq = bev.seq;
                return;
            }
            self.jr.clearEcho(rel); // raced a genuine edit: process normally
        }

        self.jr.add(.{
            .path = rel,
            .op = op,
            .cookie = bev.cookie,
            .is_dir = bev.isDir(),
            .seq = bev.seq,
        }, now) catch {};
    }

    fn verifyInstallEcho(self: *Daemon, rel: []const u8, echo: journal.Echo) bool {
        const abs = self.inst.absPath(rel) catch return false;
        defer self.alloc.free(abs);
        const st = installer.statPath(abs) catch return false;
        if (st.size < 0 or @as(u64, @intCast(st.size)) != echo.size) return false;
        const sha = installer.hashFile(abs) catch return false;
        return std.mem.eql(u8, &sha, &echo.sha256);
    }

    // ---- journal work: the announce path ----

    fn processWork(self: *Daemon, work: *journal.Work) void {
        switch (work.*) {
            .upsert => |*e| self.processUpsert(e),
            .delete => |*e| self.processDelete(e),
            .rename => |*r| self.processRename(r),
        }
    }

    fn processUpsert(self: *Daemon, e: *journal.Entry) void {
        const abs = self.inst.absPath(e.path) catch return;
        defer self.alloc.free(abs);
        const st = installer.statPath(abs) catch {
            // Vanished between event and processing: treat as a delete.
            var del = journal.Entry{ .path = e.path, .is_dir = e.is_dir, .last_seq = e.last_seq };
            self.processDelete(&del);
            return;
        };
        const is_dir = installer.isDir(st);
        const sha = if (is_dir) [_]u8{0} ** 32 else installer.hashFile(abs) catch return;

        if (self.cs.lookup(e.path)) |rec| {
            if (rec.state == .live and rec.is_dir == is_dir and
                std.mem.eql(u8, &rec.sha256, &sha) and
                rec.size == @as(u64, @intCast(@max(st.size, 0))))
            {
                // Spurious event (attrib-only or echo we didn't mark):
                // refresh identity silently, announce nothing.
                var r = rec.*;
                r.id = .{ .fsid = @intCast(st.dev), .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
                r.mtime_sec = @intCast(st.mtim.sec);
                r.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
                r.mode = @intCast(@as(u32, @intCast(st.mode)) & 0o7777);
                self.cs.upsert(e.path, r) catch {};
                return;
            }
        }

        const ver = self.cs.nextVersion();
        const rec = contentset.Record{
            .id = .{ .fsid = @intCast(st.dev), .fileid = @intCast(st.ino), .gen = @intCast(st.gen) },
            .ver = ver,
            .size = @intCast(@max(st.size, 0)),
            .mtime_sec = @intCast(st.mtim.sec),
            .mtime_nsec = @intCast(@max(st.mtim.nsec, 0)),
            .mode = @intCast(@as(u32, @intCast(st.mode)) & 0o7777),
            .is_dir = is_dir,
            .state = .live,
            .sha256 = sha,
        };
        self.cs.upsert(e.path, rec) catch return;
        self.broadcast(.{ .announce = .{
            .ver = ver,
            .is_dir = is_dir,
            .mode = rec.mode,
            .size = rec.size,
            .mtime_sec = rec.mtime_sec,
            .mtime_nsec = rec.mtime_nsec,
            .path = e.path,
            .sha256 = sha,
        } });
        log(.info, "announce {s} v=({x},{d}) size={d}{s}", .{ e.path, ver.origin, ver.seq, rec.size, if (is_dir) " dir" else "" });
    }

    fn processDelete(self: *Daemon, e: *journal.Entry) void {
        const rec = self.cs.lookup(e.path) orelse return;
        if (rec.state == .deleted) return;
        const ver = self.cs.nextVersion();
        var r = rec.*;
        r.state = .deleted;
        r.ver = ver;
        self.cs.upsert(e.path, r) catch return;
        self.broadcast(.{ .tombstone = .{ .ver = ver, .is_dir = rec.is_dir, .path = e.path } });
        log(.info, "tombstone {s} v=({x},{d})", .{ e.path, ver.origin, ver.seq });
    }

    fn processRename(self: *Daemon, r: *journal.Rename) void {
        const rec = self.cs.lookup(r.from) orelse {
            // Source unknown: treat as a plain upsert of the destination.
            var up = journal.Entry{ .path = r.to, .is_dir = r.is_dir, .last_seq = r.last_seq };
            self.processUpsert(&up);
            return;
        };
        const ver = self.cs.nextVersion();
        var dst = rec.*;
        dst.ver = ver;
        dst.state = .live;
        // Refresh identity from the destination.
        if (self.inst.absPath(r.to)) |abs| {
            defer self.alloc.free(abs);
            if (installer.statPath(abs)) |st| {
                dst.id = .{ .fsid = @intCast(st.dev), .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
                dst.size = @intCast(@max(st.size, 0));
                dst.mtime_sec = @intCast(st.mtim.sec);
                dst.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
                dst.mode = @intCast(@as(u32, @intCast(st.mode)) & 0o7777);
            } else |_| {}
        } else |_| {}
        self.cs.upsert(r.to, dst) catch return;
        var tomb = rec.*;
        tomb.state = .deleted;
        tomb.ver = ver;
        self.cs.upsert(r.from, tomb) catch return;

        self.move_cookie +%= 1;
        const cookie = self.move_cookie;
        self.broadcast(.{ .move_from = .{ .ver = ver, .is_dir = rec.is_dir, .cookie = cookie, .path = r.from } });
        self.broadcast(.{ .move_to = .{ .ver = ver, .is_dir = rec.is_dir, .cookie = cookie, .path = r.to } });
        log(.info, "rename {s} -> {s} v=({x},{d})", .{ r.from, r.to, ver.origin, ver.seq });

        if (r.dirty) {
            var up = journal.Entry{ .path = r.to, .is_dir = r.is_dir, .last_seq = r.last_seq };
            self.processUpsert(&up);
        }
    }

    // ---- peer connections ----

    fn onAccept(self: *Daemon) void {
        while (true) {
            const fd = server.acceptOne(self.listen_fd) catch |err| {
                log(.err, "accept: {s}", .{@errorName(err)});
                return;
            } orelse return;
            const p = self.alloc.create(Peer) catch {
                posix.close(fd);
                return;
            };
            p.* = Peer.init(self.alloc);
            p.adopt(fd);
            self.peers.append(self.alloc, p) catch {
                p.deinit();
                self.alloc.destroy(p);
                return;
            };
            self.registerPeerFd(p);
            self.sendHello(p);
        }
    }

    fn onPeerWritable(self: *Daemon, p: *Peer) void {
        if (p.state == .connecting) {
            _ = p.connectResult() catch {
                self.dropPeer(p, peer_mod.nowMs(), "connect failed");
                return;
            };
            log(.info, "connected to peer {s}", .{peerName(p)});
            self.sendHello(p);
            return;
        }
        p.writeReady() catch {
            self.dropPeer(p, peer_mod.nowMs(), "write failed");
        };
    }

    fn onPeerReadable(self: *Daemon, p: *Peer) void {
        p.readReady() catch {
            self.dropPeer(p, peer_mod.nowMs(), "read failed");
            return;
        };
        while (true) {
            const frame = p.popFrame() catch {
                self.dropPeer(p, peer_mod.nowMs(), "protocol violation");
                return;
            } orelse return;
            defer self.alloc.free(frame);
            const msg = protocol.decode(frame[4..]) catch {
                self.dropPeer(p, peer_mod.nowMs(), "bad frame");
                return;
            };
            self.onMessage(p, msg);
            if (p.state == .closed) return; // we dropped it mid-dispatch
        }
    }

    fn sendHello(self: *Daemon, p: *Peer) void {
        var nonce: [protocol.nonce_len]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        p.send(.{ .hello = .{
            .proto = protocol.protocol_version,
            .node_id = self.cfg.node_id,
            .psk = self.psk,
            .nonce = nonce,
        } }) catch {};
        self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    fn onMessage(self: *Daemon, p: *Peer, msg: protocol.Message) void {
        const now = peer_mod.nowMs();
        switch (msg) {
            .hello => |m| {
                p.checkHello(m, self.cfg.node_id, self.psk) catch |err| {
                    self.dropPeer(p, now, @errorName(err));
                    return;
                };
                log(.info, "peer {s} handshake OK ({s})", .{ p.node_id.?, if (p.outbound) "outbound" else "inbound" });
                if (self.dedupMesh(p, now)) return; // p lost the dedup
                self.sendResyncReq(p);
            },
            .announce => |m| self.onAnnounce(p, m),
            .fetch_req => |m| self.onFetchReq(p, m),
            .fetch_data => |m| self.onFetchData(p, m),
            .fetch_ack => |m| self.onFetchAck(p, m),
            .tombstone => |m| self.onTombstone(p, m),
            .resync_req => |m| self.onResyncReq(p, m),
            .resync_entry => |m| self.onResyncEntry(p, m),
            .resync_done => |count| self.onResyncDone(p, count),
            .move_from => |m| {
                if (p.state != .ready) return;
                p.noteRemoteMove(m.cookie, m.path, m.ver, m.is_dir, now) catch {};
            },
            .move_to => |m| self.onMoveTo(p, m),
            .nack => |m| {
                log(.warn, "NACK from {s}: {s} v=({x},{d}) code={d}", .{ peerName(p), m.path, m.ver.origin, m.ver.seq, m.code });
                if (m.code == nack_missing) self.inst.abortFetch(m.path);
            },
        }
    }

    /// One TCP conn per pair: the larger node_id keeps its OUTBOUND conn.
    /// Returns true if p itself was dropped (caller must stop using p —
    /// inbound peers are queued for destruction).
    fn dedupMesh(self: *Daemon, p: *Peer, now: i64) bool {
        for (self.peers.items) |q| {
            if (q == p or q.node_id == null or p.node_id == null) continue;
            if (!std.mem.eql(u8, q.node_id.?, p.node_id.?)) continue;
            if (q.state != .ready and q.state != .handshake) continue;
            const we_keep_outbound = std.mem.order(u8, self.cfg.node_id, p.node_id.?) == .gt;
            const drop_p = if (we_keep_outbound) !p.outbound else p.outbound;
            if (drop_p) {
                self.dropPeer(p, now, "mesh dedup");
                return true;
            }
            self.dropPeer(q, now, "mesh dedup");
            return false;
        }
        return false;
    }

    fn broadcast(self: *Daemon, msg: protocol.Message) void {
        const now = peer_mod.nowMs();
        var i: usize = 0;
        while (i < self.peers.items.len) : (i += 1) {
            const p = self.peers.items[i];
            if (p.state != .ready) continue;
            var failed = false;
            p.send(msg) catch {
                failed = true;
            };
            if (failed) {
                self.dropPeer(p, now, "saturated"); // may swapRemove: re-examine i
                if (i < self.peers.items.len and self.peers.items[i] != p) i -%= 1;
                continue;
            }
            if (p.wantsWrite())
                self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
        }
    }

    // ---- replication message handlers ----

    fn onAnnounce(self: *Daemon, p: *Peer, m: protocol.Announce) void {
        if (p.state != .ready) return;
        // A fetch already in flight for this path+ver (the unpaired-MOVE_TO
        // fallback): the sender's pre-chunk ANNOUNCE carries the real meta.
        if (self.inst.fetchInProgress(m.path)) {
            if (self.incoming.getPtr(m.path)) |meta| {
                if (meta.ver.eql(m.ver)) {
                    meta.size = m.size;
                    meta.sha256 = m.sha256;
                    meta.mode = m.mode;
                    meta.mtime_sec = m.mtime_sec;
                    meta.mtime_nsec = m.mtime_nsec;
                    meta.deadline_ms = peer_mod.nowMs() + fetch_timeout_ms;
                    self.inst.updateFetchMeta(m.path, m.size, m.sha256, m.mode, m.mtime_sec, m.mtime_nsec);
                    return;
                }
            }
        }
        const stored = self.cs.lookup(m.path);
        if (stored) |rec| {
            switch (contentset.relate(m.ver, rec.ver)) {
                .same, .older => return,
                .conflict_stored_wins => return, // we win; peer converges via our ANNOUNCE
                .newer => {},
                .conflict_incoming_wins => {
                    log(.info, "conflict {s}: peer {s} wins, quarantining local", .{ m.path, peerName(p) });
                    self.inst.quarantine(m.path) catch {};
                },
            }
        }
        if (m.is_dir) {
            const abs = self.inst.absPath(m.path) catch return;
            defer self.alloc.free(abs);
            std.fs.cwd().makePath(abs) catch {};
            self.upsertFromWire(m.path, m.ver, true, m.mode, 0, m.mtime_sec, m.mtime_nsec, m.sha256);
            return;
        }
        self.startFetch(p, m.path, m.ver, m.size, m.sha256, m.mode, m.mtime_sec, m.mtime_nsec);
    }

    fn startFetch(self: *Daemon, p: *Peer, path: []const u8, ver: Version, size: u64, sha: [32]u8, mode: u16, mtime_sec: i64, mtime_nsec: u32) void {
        const meta = Incoming{ .ver = ver, .size = size, .sha256 = sha, .mode = mode, .mtime_sec = mtime_sec, .mtime_nsec = mtime_nsec, .deadline_ms = peer_mod.nowMs() + fetch_timeout_ms };
        const gop = self.incoming.getOrPut(path) catch return;
        if (!gop.found_existing)
            gop.key_ptr.* = self.alloc.dupe(u8, path) catch return;
        gop.value_ptr.* = meta;

        self.inst.beginFetch(path, meta) catch |err| {
            log(.warn, "beginFetch {s}: {s}", .{ path, @errorName(err) });
            return;
        };
        p.send(.{ .fetch_req = .{ .ver = ver, .path = path } }) catch {};
        self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    const nack_stale: u16 = 1;
    const nack_missing: u16 = 2;

    fn onFetchReq(self: *Daemon, p: *Peer, m: protocol.PathVer) void {
        if (p.state != .ready) return;
        const rec = self.cs.lookup(m.path) orelse {
            self.sendNack(p, m.path, m.ver, nack_missing);
            return;
        };
        if (rec.state != .live or rec.is_dir) {
            self.sendNack(p, m.path, m.ver, nack_missing);
            return;
        }
        if (!rec.ver.eql(m.ver)) {
            // Stale request: the requester will re-fetch from the fresh
            // ANNOUNCE we proactively emit.
            self.sendNack(p, m.path, m.ver, nack_stale);
            p.send(.{ .announce = .{
                .ver = rec.ver,
                .is_dir = false,
                .mode = rec.mode,
                .size = rec.size,
                .mtime_sec = rec.mtime_sec,
                .mtime_nsec = rec.mtime_nsec,
                .path = m.path,
                .sha256 = rec.sha256,
            } }) catch {};
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
            return;
        }
        // Meta first: the unpaired-MOVE_TO fetch path on the receiver has
        // no ANNOUNCE yet; in the normal flow this is an idempotent no-op.
        p.send(.{ .announce = .{
            .ver = rec.ver,
            .is_dir = false,
            .mode = rec.mode,
            .size = rec.size,
            .mtime_sec = rec.mtime_sec,
            .mtime_nsec = rec.mtime_nsec,
            .path = m.path,
            .sha256 = rec.sha256,
        } }) catch return;
        const abs = self.inst.absPath(m.path) catch return;
        defer self.alloc.free(abs);
        const fd = posix.open(abs, .{ .ACCMODE = .RDONLY }, 0) catch {
            self.sendNack(p, m.path, m.ver, nack_missing);
            return;
        };
        defer posix.close(fd);
        var offset: u64 = 0;
        var buf: [installer.chunk_size]u8 = undefined;
        while (offset < rec.size) {
            const want: usize = @intCast(@min(@as(u64, installer.chunk_size), rec.size - offset));
            const n = posix.read(fd, buf[0..want]) catch return;
            if (n == 0) return; // truncated mid-serve: receiver's hash check catches it
            p.send(.{ .fetch_data = .{ .ver = m.ver, .offset = offset, .path = m.path, .data = buf[0..n] } }) catch return;
            offset += n;
        }
        if (p.wantsWrite())
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    fn onFetchData(self: *Daemon, p: *Peer, m: protocol.FetchData) void {
        if (p.state != .ready) return;
        self.inst.writeChunk(m.path, m.ver, m.offset, m.data) catch |err| {
            log(.warn, "writeChunk {s}: {s}", .{ m.path, @errorName(err) });
            self.inst.abortFetch(m.path);
            return;
        };
        if (!self.inst.fetchComplete(m.path)) return;

        const meta = self.incoming.get(m.path) orelse {
            self.inst.abortFetch(m.path);
            return;
        };
        // Echo marker BEFORE the rename: the resulting kernel event must
        // find it (rule 6).
        self.jr.noteEcho(m.path, .install, meta.sha256, meta.size) catch {};
        const installed = self.inst.complete(m.path) catch |err| {
            log(.warn, "install {s} failed: {s}", .{ m.path, @errorName(err) });
            if (self.incoming.fetchRemove(m.path)) |kv| self.alloc.free(kv.key);
            return;
        };
        if (self.incoming.fetchRemove(m.path)) |kv| self.alloc.free(kv.key);

        self.upsertFromWire(m.path, m.ver, false, meta.mode, meta.size, meta.mtime_sec, meta.mtime_nsec, installed);
        p.send(.{ .fetch_ack = .{ .ver = m.ver, .path = m.path, .sha256 = installed } }) catch {};
        self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
        log(.info, "installed {s} v=({x},{d}) size={d}", .{ m.path, m.ver.origin, m.ver.seq, meta.size });
    }

    fn onFetchAck(self: *Daemon, p: *Peer, m: protocol.FetchAck) void {
        if (p.state != .ready) return;
        const rec = self.cs.lookup(m.path) orelse return;
        if (!rec.ver.eql(m.ver)) return; // we've moved on
        if (std.mem.eql(u8, &rec.sha256, &m.sha256)) return;
        // Receiver installed different bytes: re-serve once it re-requests.
        log(.warn, "FETCH_ACK hash mismatch for {s} from {s}; expecting re-fetch", .{ m.path, peerName(p) });
    }

    fn onTombstone(self: *Daemon, p: *Peer, m: protocol.Tombstone) void {
        if (p.state != .ready) return;
        if (self.cs.lookup(m.path)) |rec| {
            switch (contentset.relate(m.ver, rec.ver)) {
                .same, .older, .conflict_stored_wins => return,
                .newer => {},
                .conflict_incoming_wins => {
                    // Loser content is preserved (DFSR ConflictAndDeleted).
                    self.inst.quarantine(m.path) catch {};
                },
            }
        }
        self.inst.tombstone(m.path, m.is_dir) catch |err| {
            log(.warn, "tombstone {s}: {s}", .{ m.path, @errorName(err) });
        };
        var rec = contentset.Record{ .ver = m.ver, .is_dir = m.is_dir, .state = .deleted };
        if (self.cs.lookup(m.path)) |old| rec.id = old.id;
        self.cs.upsert(m.path, rec) catch {};
        log(.info, "applied tombstone {s} v=({x},{d})", .{ m.path, m.ver.origin, m.ver.seq });
    }

    fn onMoveTo(self: *Daemon, p: *Peer, m: protocol.Move) void {
        if (p.state != .ready) return;
        var mv = p.takeRemoteMove(m.cookie) orelse {
            // Unpaired TO: sender moved it in from outside its tree; we
            // need the content.
            self.startFetchVer(p, m.path, m.ver);
            return;
        };
        defer p.freeMove(&mv);

        const from_rec = self.cs.lookup(mv.path);
        if (from_rec == null) {
            self.startFetchVer(p, m.path, m.ver);
            return;
        }
        // Apply the rename locally (echo-suppressed both halves).
        const abs_from = self.inst.absPath(mv.path) catch return;
        defer self.alloc.free(abs_from);
        const abs_to = self.inst.absPath(m.path) catch return;
        defer self.alloc.free(abs_to);
        var sha = [_]u8{0} ** 32;
        var size: u64 = 0;
        if (installer.statPath(abs_from)) |st| {
            size = @intCast(@max(st.size, 0));
            if (!installer.isDir(st)) {
                sha = installer.hashFile(abs_from) catch sha;
            }
        } else |_| {}
        self.jr.noteEcho(mv.path, .move_from, sha, size) catch {};
        self.jr.noteEcho(m.path, .install, sha, size) catch {};
        posix.rename(abs_from, abs_to) catch {
            // From-path missing locally: fetch the destination instead.
            self.jr.clearEcho(mv.path);
            self.jr.clearEcho(m.path);
            self.startFetchVer(p, m.path, m.ver);
            return;
        };

        var dst = from_rec.?.*;
        dst.ver = m.ver;
        dst.state = .live;
        if (installer.statPath(abs_to)) |st| {
            dst.id = .{ .fsid = @intCast(st.dev), .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
            dst.size = @intCast(@max(st.size, 0));
            dst.mtime_sec = @intCast(st.mtim.sec);
            dst.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
        } else |_| {}
        self.cs.upsert(m.path, dst) catch {};
        var tomb = from_rec.?.*;
        tomb.state = .deleted;
        tomb.ver = m.ver;
        self.cs.upsert(mv.path, tomb) catch {};
        log(.info, "applied rename {s} -> {s} v=({x},{d})", .{ mv.path, m.path, m.ver.origin, m.ver.seq });
    }

    fn startFetchVer(self: *Daemon, p: *Peer, path: []const u8, ver: Version) void {
        // Content unknown (unpaired MOVE_TO): we have no announced meta;
        // request and take whatever meta the FETCH serves.  mode/mtime
        // default; a subsequent ANNOUNCE refreshes them.
        self.startFetch(p, path, ver, std.math.maxInt(u64), [_]u8{0} ** 32, 0o644, 0, 0);
    }

    fn sendNack(self: *Daemon, p: *Peer, path: []const u8, ver: Version, code: u16) void {
        p.send(.{ .nack = .{ .ver = ver, .code = code, .path = path } }) catch {};
        self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    fn upsertFromWire(self: *Daemon, path: []const u8, ver: Version, is_dir: bool, mode: u16, size: u64, mtime_sec: i64, mtime_nsec: u32, sha: [32]u8) void {
        var rec = contentset.Record{
            .ver = ver,
            .size = size,
            .mtime_sec = mtime_sec,
            .mtime_nsec = mtime_nsec,
            .mode = mode,
            .is_dir = is_dir,
            .state = .live,
            .sha256 = sha,
        };
        // Identity from disk (present after install/mkdir).
        if (self.inst.absPath(path)) |abs| {
            defer self.alloc.free(abs);
            if (installer.statPath(abs)) |st| {
                rec.id = .{ .fsid = @intCast(st.dev), .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
                if (is_dir) {
                    rec.size = 0;
                } else {
                    rec.size = @intCast(@max(st.size, 0));
                }
            } else |_| {}
        } else |_| {}
        self.cs.upsert(path, rec) catch {};
    }

    // ---- resync ----

    fn sendResyncReq(self: *Daemon, p: *Peer) void {
        const vec = resync.buildVector(&self.cs);
        p.send(.{ .resync_req = vec }) catch {};
        self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    fn onResyncReq(self: *Daemon, p: *Peer, m: protocol.ResyncReq) void {
        if (p.state != .ready) return;
        var count: u64 = 0;
        var it = self.cs.map.iterator();
        while (it.next()) |e| {
            if (resync.vectorCovers(&m, e.value_ptr.ver)) continue;
            const rec = e.value_ptr.*;
            p.send(.{ .resync_entry = .{
                .ver = rec.ver,
                .is_dir = rec.is_dir,
                .state = rec.state,
                .mode = rec.mode,
                .size = rec.size,
                .mtime_sec = rec.mtime_sec,
                .mtime_nsec = rec.mtime_nsec,
                .path = e.key_ptr.*,
                .sha256 = rec.sha256,
            } }) catch return;
            count += 1;
        }
        p.send(.{ .resync_done = count }) catch return;
        if (p.wantsWrite())
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
        log(.info, "served RESYNC to {s}: {d} entries", .{ peerName(p), count });
    }

    fn onResyncEntry(self: *Daemon, p: *Peer, m: protocol.ResyncEntry) void {
        if (p.state != .ready) return;
        switch (resync.entryAction(&self.cs, m)) {
            .ignore => {},
            .tombstone => {
                self.inst.tombstone(m.path, m.is_dir) catch {};
                var rec = contentset.Record{ .ver = m.ver, .is_dir = m.is_dir, .state = .deleted };
                if (self.cs.lookup(m.path)) |old| rec.id = old.id;
                self.cs.upsert(m.path, rec) catch {};
            },
            .adopt => {
                self.upsertFromWire(m.path, m.ver, m.is_dir, m.mode, m.size, m.mtime_sec, m.mtime_nsec, m.sha256);
            },
            .fetch => {
                if (m.is_dir) {
                    const abs = self.inst.absPath(m.path) catch return;
                    defer self.alloc.free(abs);
                    std.fs.cwd().makePath(abs) catch {};
                    self.upsertFromWire(m.path, m.ver, true, m.mode, 0, m.mtime_sec, m.mtime_nsec, m.sha256);
                } else {
                    self.startFetch(p, m.path, m.ver, m.size, m.sha256, m.mode, m.mtime_sec, m.mtime_nsec);
                }
            },
        }
    }

    fn onResyncDone(self: *Daemon, p: *Peer, count: u64) void {
        if (p.state != .ready) return;
        log(.info, "RESYNC from {s} complete: {d} entries", .{ peerName(p), count });
        if (!self.resynced) {
            self.resynced = true;
            // Post-join scan: local-only files (never in the group) join
            // the mesh as fresh local content.
            const stats = resync.scan(self.alloc, self.cfg.replicated_path, &self.cs, &self.jr, peer_mod.nowMs()) catch return;
            log(.info, "post-join scan: seen={d} new={d} mod={d} del={d}", .{
                stats.seen, stats.announced_new, stats.announced_modified, stats.announced_deleted,
            });
        }
    }

    // ---- periodic ----

    fn timerPass(self: *Daemon) void {
        const now = peer_mod.nowMs();

        // Journal debounce expiries -> announce.
        if (self.resynced) {
            var works: std.ArrayList(journal.Work) = .empty;
            self.jr.collectReady(now, &works) catch {};
            for (works.items) |*w| self.processWork(w);
            for (works.items) |*w| self.jr.freeWork(w);
            works.deinit(self.alloc);
        }

        // Reconnect due outbound peers.
        for (self.peers.items) |p| {
            if (p.outbound and p.state == .closed and p.addr != null and now >= p.next_retry_ms) {
                const fd = p.dial(p.addr.?) catch {
                    p.disconnected(now);
                    continue;
                };
                self.stageChange(@intCast(fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, p);
                self.stageChange(@intCast(fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
            }
            // Expired unpaired remote MOVE_FROMs = moved out of tree.
            var expired: std.ArrayList(peer_mod.RemoteMove) = .empty;
            p.sweepRemoteMoves(now, &expired) catch {};
            for (expired.items) |*mv| {
                self.inst.tombstone(mv.path, mv.is_dir) catch {};
                var rec = contentset.Record{ .ver = mv.ver, .is_dir = mv.is_dir, .state = .deleted };
                if (self.cs.lookup(mv.path)) |old| rec.id = old.id;
                self.cs.upsert(mv.path, rec) catch {};
                p.freeMove(mv);
            }
            expired.deinit(self.alloc);
        }

        // Rescan floor (ring overflow / unknown-dir events).
        if (self.need_rescan and now - self.last_rescan_ms >= rescan_cooldown_ms and self.resynced) {
            self.need_rescan = false;
            self.last_rescan_ms = now;
            const stats = resync.scan(self.alloc, self.cfg.replicated_path, &self.cs, &self.jr, now) catch return;
            log(.info, "rescan: seen={d} new={d} mod={d} del={d}", .{
                stats.seen, stats.announced_new, stats.announced_modified, stats.announced_deleted,
            });
        }

        // Fetch timeouts: abandoned transfers are re-driven by the next
        // ANNOUNCE or resync round.
        var expired_f: std.ArrayList([]const u8) = .empty;
        defer expired_f.deinit(self.alloc);
        var iit = self.incoming.iterator();
        while (iit.next()) |e| {
            if (e.value_ptr.deadline_ms <= now)
                expired_f.append(self.alloc, e.key_ptr.*) catch break;
        }
        for (expired_f.items) |path| {
            log(.warn, "fetch {s} timed out; aborting", .{path});
            self.inst.abortFetch(path);
            if (self.incoming.fetchRemove(path)) |kv| self.alloc.free(kv.key);
        }

        // Ring-seq checkpoint (USN analog resume point).
        if (now - self.last_checkpoint_ms >= checkpoint_interval_ms) {
            self.last_checkpoint_ms = now;
            self.cs.checkpoint(self.jr.high_seq) catch {};
            self.cs.flush() catch {};
        }
    }

    fn cleanStaging(self: *Daemon) void {
        var dir = std.fs.cwd().openDir(self.inst.staging, .{ .iterate = true }) catch return;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch return) |ent| {
            if (std.mem.endsWith(u8, ent.name, ".part"))
                dir.deleteFile(ent.name) catch {};
        }
    }
};

fn peerName(p: *Peer) []const u8 {
    return p.node_id orelse "?";
}
