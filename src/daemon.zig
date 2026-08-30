//! daemon.zig — the brfsd core: one kqueue event loop + one drainer thread
//! + one completion worker.
//!
//! Thread model (locked decision 7): the drainer thread owns the ring pop
//! side (blocking read on /dev/brfs, batch push through a mutex-guarded
//! queue, pipe-trick wakeup).  The completion worker owns the blocking
//! half of installs (fsync/rename — a 200MB fsync stalled the core loop
//! for tens of seconds on the rig and snowballed mesh-wide).  Everything
//! else — journal, content set, peer protocol, installer fetch side,
//! resync — runs on the single core thread, so no locking exists anywhere
//! on the replication logic.  The completion worker is strictly FIFO and
//! the ONLY writer of install results; ordering rules: an in-flight or
//! completing fetch is the effective stored version for incoming announces
//! (onAnnounce guard), and a result that lands under a newer stored record
//! is reverted on disk (onInstalled).
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
const ctl = @import("ctl.zig");
const tls_mod = @import("tls.zig");
const guard_mod = @import("guard.zig");

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
const gc_interval_ms: i64 = 3_600_000; // tombstone GC cadence (gap #7)
const repush_interval_ms: i64 = 3_600_000; // watch-root re-push cadence (flag-strip mitigation)
const max_violations: u32 = 8;

/// udata sentinel marking ctl-socket client conns on the kqueue (peers
/// carry *Peer; ctl conns carry this tag's address).
var ctl_conn_tag: u8 = 0;

pub const Level = enum { info, warn, err };

pub fn log(comptime level: Level, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const ts = std.time.milliTimestamp();
    const prefix = std.fmt.bufPrint(&buf, "brfsd[{s}] {d}: ", .{ @tagName(level), ts }) catch return;
    const msg = std.fmt.bufPrint(buf[prefix.len..], fmt ++ "\n", args) catch return;
    _ = posix.write(2, buf[0 .. prefix.len + msg.len]) catch {};
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
    // Blocking read: this thread exists to own the ring pop side.  The
    // device was opened WITHOUT O_NONBLOCK (F_SETFL cannot toggle it on a
    // cdev).  The thread exits only on device errors (kmod unload wakes
    // readers with ENXIO); process exit reaps it.
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
    /// The fetch detached into the completion worker (blocking fsync +
    /// rename off the core loop).  Completing entries are exempt from the
    /// stall-timeout sweep — the worker owns them.
    completing: bool = false,
    /// Gap #10 source-selection: fnv1a64(node_id) of every source already
    /// tried for this fetch — the announce/resync source first, then NACK
    /// fallbacks.  Bounded by max_peers (full mesh, no relaying).
    tried: [config.max_peers]u64 = [_]u64{0} ** config.max_peers,
    tried_n: u8 = 0,

    fn markTried(self: *Incoming, node_id: []const u8) void {
        if (self.wasTried(node_id)) return;
        if (self.tried_n >= self.tried.len) return;
        self.tried[self.tried_n] = std.hash.Fnv1a_64.hash(node_id);
        self.tried_n += 1;
    }

    fn wasTried(self: *const Incoming, node_id: []const u8) bool {
        const h = std.hash.Fnv1a_64.hash(node_id);
        for (self.tried[0..self.tried_n]) |h0| {
            if (h0 == h) return true;
        }
        return false;
    }
};

const fetch_timeout_ms: i64 = 30_000;

/// Completion worker: owns the blocking half of installs (fsync, divergent-
/// destination hash/quarantine, rename, meta) so the core loop never waits
/// on a ZFS TXG.  Exactly ONE worker, FIFO: results land in submission
/// order — the same-path version-ordering argument depends on it.
/// Core->worker: mutex-guarded job queue + kick pipe (kqueue on the worker,
/// close(kick_wr) = drain-and-exit per house rules).  Worker->core:
/// mutex-guarded result queue + the shared wake pipe.
const CompletionWorker = struct {
    alloc: Allocator,
    inst: *installer.Installer,
    kick_rd: posix.fd_t,
    kick_wr: posix.fd_t,
    wake_wr: posix.fd_t,
    mutex: std.Thread.Mutex = .{},
    jobs: std.ArrayList(installer.CompleteJob) = .empty,
    res_mutex: std.Thread.Mutex = .{},
    results: std.ArrayList(installer.CompleteResult) = .empty,

    fn submit(self: *CompletionWorker, job: installer.CompleteJob) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.jobs.append(self.alloc, job) catch {
            // OOM: drop the job (the file stays staged; the next announce/
            // rescan re-drives the fetch).  Free what we own.
            posix.close(job.fd);
            self.alloc.free(job.path);
            if (job.ack_peer) |ap| self.alloc.free(ap);
            return;
        };
        _ = posix.write(self.kick_wr, "x") catch {};
    }

    fn popJob(self: *CompletionWorker) ?installer.CompleteJob {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.jobs.items.len == 0) return null;
        return self.jobs.orderedRemove(0);
    }

    fn pushResult(self: *CompletionWorker, res: installer.CompleteResult) void {
        self.res_mutex.lock();
        defer self.res_mutex.unlock();
        self.results.append(self.alloc, res) catch {
            self.alloc.free(res.job.path);
            if (res.job.ack_peer) |ap| self.alloc.free(ap);
            return;
        };
        _ = posix.write(self.wake_wr, "x") catch {};
    }

    fn takeResults(self: *CompletionWorker, out: *std.ArrayList(installer.CompleteResult)) void {
        self.res_mutex.lock();
        defer self.res_mutex.unlock();
        out.appendSlice(self.alloc, self.results.items) catch return;
        self.results.clearRetainingCapacity();
    }
};

/// Thread entry for the completion worker (spawned by Daemon.run).
pub fn completionEntry(comp: *CompletionWorker) void {
    completionMain(comp);
}

fn completionMain(comp: *CompletionWorker) void {
    const kq = kqueue();
    if (kq < 0) {
        log(.err, "completion worker: kqueue failed — installs will stall", .{});
        return;
    }
    var reg = [1]KEvent{makeKevent(@intCast(comp.kick_rd), c_event.EVFILT_READ, c_event.EV_ADD, null)};
    var nchanges: c_int = 1; // registration + wait in ONE kevent (house rule)
    var evlist: [4]KEvent = undefined;
    var alive = true;
    while (alive) {
        const nev = kevent(kq, if (nchanges > 0) &reg else null, nchanges, &evlist, evlist.len, null);
        nchanges = 0;
        if (nev < 0) continue;
        for (evlist[0..@intCast(nev)]) |*ev| {
            // close(kick_wr) sets a PERSISTENT EV_EOF: drain what remains
            // and exit (no new jobs can arrive — the core is shutting down).
            if (ev.flags & c_event.EV_EOF != 0) alive = false;
        }
        var trash: [64]u8 = undefined;
        while (true) {
            const n = posix.read(comp.kick_rd, &trash) catch break;
            if (n == 0) break;
        }
        while (comp.popJob()) |job| {
            var j = job;
            var res = installer.CompleteResult{ .job = j };
            if (comp.inst.finishComplete(&j)) |_| {} else |e| {
                res.err = e;
            }
            comp.pushResult(res);
        }
    }
}

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
    ctl_fd: posix.fd_t = -1,
    wake_rd: posix.fd_t = -1,
    evq: EventQueue,
    peers: std.ArrayList(*Peer) = .empty,
    changes: std.ArrayList(KEvent) = .empty, // staged changelist
    batch: std.ArrayList(events.Event) = .empty, // drained kernel events
    incoming: std.StringHashMap(Incoming),
    dead: std.ArrayList(*Peer) = .empty,
    move_cookie: u32 = 0,
    /// The replicated tree's fsid in kmod encoding (f_fsid pair — NOT
    /// st_dev).  One fs per watched tree (no sub-mounts, documented POC
    /// limitation).
    tree_fsid: u64 = 0,
    resynced: bool = false,
    need_rescan: bool = false,
    /// Gap #17 mass-delete guard (guard.zig): local tombstone storm latch.
    guard: guard_mod.Guard = .{},
    /// Set by main for SIGHUP reload (gap #19); null in unit tests.
    cfg_path: ?[*:0]const u8 = null,
    /// Daemon-owned PSK after a SIGHUP reload (the startup PSK is borrowed
    /// from main; reloads must not free it).
    psk_owned: ?[]u8 = null,
    /// Gap #16: the watched fs is not the one the content set was stamped
    /// against (forced unmount / rebuilt fs) — scans, the root re-push,
    /// and the watch registration are frozen until the mount is fixed and
    /// the daemon restarted.
    fs_frozen: bool = false,
    /// Gap #7 ack horizon: the last version vector each member announced
    /// (from its RESYNC_REQ), keyed by fnv1a64(node_id).  Refreshed at
    /// every handshake (both sides RESYNC_REQ on ready) and every
    /// operator resync, so vectors track liveness for free.
    member_vectors: [config.max_peers]resync.MemberVector =
        [_]resync.MemberVector{.{}} ** config.max_peers,
    last_rescan_ms: i64 = 0,
    last_checkpoint_ms: i64 = 0,
    last_gc_ms: i64 = 0,
    last_repush_ms: i64 = 0,
    comp: CompletionWorker,
    comp_thread: ?std.Thread = null,
    running: bool = true,
    tls_ctx: ?tls_mod.TlsContext = null,

    pub fn init(alloc: Allocator, cfg: *const config.Config, psk: []const u8, dev_fd: posix.fd_t, wake_rd: posix.fd_t, wake_wr: posix.fd_t) !Daemon {
        var cs = try ContentSet.open(alloc, cfg.state_dir, cfg.node_id);
        errdefer cs.close();
        const inst = try installer.Installer.init(alloc, cfg.replicated_path, cfg.state_dir);

        // TLS context (optional: only when cert+key are configured).
        var tls_ctx: ?tls_mod.TlsContext = null;
        if (cfg.tlsEnabled()) {
            const ca: ?[*:0]const u8 = if (cfg.tls_ca.len > 0)
                @ptrCast(cfg.tls_ca.ptr)
            else
                null;
            tls_ctx = tls_mod.TlsContext.init(
                @ptrCast(cfg.tls_cert.ptr),
                @ptrCast(cfg.tls_key.ptr),
                ca,
                cfg.tls_ktls,
            ) catch |err| {
                log(.err, "TLS init failed: {s}", .{@errorName(err)});
                return error.TlsInitFailed;
            };
            log(.info, "TLS enabled (KTLS {s})", .{if (cfg.tls_ktls) "offload if kernel supports it" else "disabled by tls_ktls=false"});
        }

        // Completion-worker kick pipe (both ends non-blocking; the worker
        // drops wakeups on a full pipe — one is already pending).
        const kpfds = try posix.pipe();
        var fl = fcntl(kpfds[0], F_GETFL, @as(c_int, 0));
        _ = fcntl(kpfds[0], F_SETFL, fl | O_NONBLOCK);
        fl = fcntl(kpfds[1], F_GETFL, @as(c_int, 0));
        _ = fcntl(kpfds[1], F_SETFL, fl | O_NONBLOCK);

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
            .tls_ctx = tls_ctx,
            // inst back-pointer is wired in run() (the Daemon is moved by
            // value out of init — &self.inst here would dangle).
            .comp = .{ .alloc = alloc, .inst = undefined, .kick_rd = kpfds[0], .kick_wr = kpfds[1], .wake_wr = wake_wr },
        };
    }

    fn stageChange(self: *Daemon, ident: usize, filter: c_short, flags: c_ushort, udata: ?*anyopaque) void {
        self.changes.append(self.alloc, makeKevent(ident, filter, flags, udata)) catch {};
    }

    fn registerPeerFd(self: *Daemon, p: *Peer) void {
        // READ is armed only once the socket is actually connected: reading
        // a connecting socket whose dial was refused yields the pending
        // connect error (ECONNREFUSED), poisoning the conn for no reason.
        if (p.state != .connecting)
            self.stageChange(@intCast(p.fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, p);
        if (p.state == .connecting or p.state == .tls_handshake or p.wantsWrite())
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    fn dropPeer(self: *Daemon, p: *Peer, now_ms: i64, why: []const u8) void {
        if (p.state == .closed) return;
        log(.warn, "peer {s} dropped: {s} ({s} fd={d})", .{
            p.node_id orelse "?",                      why,
            if (p.outbound) "outbound" else "inbound", p.fd,
        });
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

        // The Daemon's address is stable here (init moved it into the
        // caller's frame): wire the worker's installer pointer and spawn.
        self.comp.inst = &self.inst;
        self.comp_thread = try std.Thread.spawn(.{}, completionEntry, .{&self.comp});

        self.kq = kqueue();
        if (self.kq < 0) return error.KqueueFailed;

        var mask = posix.sigemptyset();
        _ = std.c.sigaddset(&mask, 15);
        _ = std.c.sigaddset(&mask, 2);
        _ = std.c.sigaddset(&mask, 1); // SIGHUP: config reload (gap #19)
        _ = std.c.sigprocmask(std.c.SIG.BLOCK, &mask, null);
        // nohup(1)/daemon(8) supervisors start us with SIGHUP set to
        // SIG_IGN, and EVFILT_SIGNAL never reports an ignored signal —
        // reset the disposition to SIG_DFL (it stays blocked, so there is
        // still no synchronous delivery; the knote fires).
        const dfl = posix.Sigaction{
            .handler = .{ .handler = posix.SIG.DFL },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(1, &dfl, null);
        self.stageChange(15, c_event.EVFILT_SIGNAL, c_event.EV_ADD, null);
        self.stageChange(2, c_event.EVFILT_SIGNAL, c_event.EV_ADD, null);
        self.stageChange(1, c_event.EVFILT_SIGNAL, c_event.EV_ADD, null);
        self.stageChange(@intCast(self.wake_rd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, null);

        // Root dir index entry so events under the root resolve.
        const root_st = try installer.statPath(self.cfg.replicated_path);
        self.tree_fsid = try installer.fsidOf(self.cfg.replicated_path);
        try self.cs.indexRoot(self.tree_fsid, @intCast(root_st.ino));

        // Gap #16 forced-unmount guard, startup half: the content set is
        // married to the fsid stamped on first start.  A mismatch means
        // the path no longer resolves to the watched filesystem (umount -f
        // leaves the bare mountpoint on the parent fs; a rebuilt fs has a
        // new fsid) — everything under it would LOOK deleted.  Freeze:
        // drop the watch registration (it would flag the WRONG fs), run no
        // scans, announce nothing local.  Recovery: fix the mount, restart
        // (fsids are mount-stable on UFS/ZFS); wipe state_dir only when
        // the fs was legitimately rebuilt.
        if (self.cs.root_fsid == 0) {
            self.cs.setRootFsid(self.tree_fsid) catch {};
        } else if (self.cs.root_fsid != self.tree_fsid) {
            self.fs_frozen = true;
            events.delRoot(self.dev_fd, self.cfg.replicated_path) catch {};
            log(.err, "watched root fsid {x} != stamped {x}: filesystem unmounted/rebuilt — replication FROZEN until restart with the correct mount", .{ self.tree_fsid, self.cs.root_fsid });
        }

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

        // Operator control socket (non-fatal: brfsctl degrades to stats).
        if (ctl.listen(ctl.sock_path)) |fd| {
            self.ctl_fd = fd;
            self.stageChange(@intCast(fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, null);
            log(.info, "control socket: {s}", .{ctl.sock_path});
        } else |err| {
            log(.warn, "control socket {s} unavailable: {s}", .{ ctl.sock_path, @errorName(err) });
        }

        // Startup reconciliation (gap #8): a non-primary with an empty set
        // pulls before announcing; everyone else scans now.
        self.resynced = self.cfg.primary or self.cs.map.count() > 0;
        if (self.resynced and !self.fs_frozen) {
            const stats = try resync.scan(alloc, self.cfg.replicated_path, &self.cs, &self.jr, peer_mod.nowMs(), self.scanInflight());
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
                    if (ev.ident == 1) {
                        log(.info, "SIGHUP: reloading config", .{});
                        self.reloadConfig();
                    } else {
                        log(.info, "signal {d}: shutting down", .{ev.ident});
                        self.running = false;
                    }
                } else if (ev.filter == c_event.EVFILT_READ and ev.udata == null and @as(posix.fd_t, @intCast(ev.ident)) == self.wake_rd) {
                    self.onWakePipe();
                } else if (ev.filter == c_event.EVFILT_READ and ev.udata == null and @as(posix.fd_t, @intCast(ev.ident)) == self.listen_fd) {
                    self.onAccept();
                } else if (ev.filter == c_event.EVFILT_READ and ev.udata == null and @as(posix.fd_t, @intCast(ev.ident)) == self.ctl_fd) {
                    self.onCtlAccept();
                } else if (ev.udata) |ud| {
                    if (ud == @as(*anyopaque, @ptrCast(&ctl_conn_tag))) {
                        if (ev.filter == c_event.EVFILT_READ)
                            self.onCtlReadable(@intCast(ev.ident));
                        continue;
                    }
                    const p: *Peer = @ptrCast(@alignCast(ud));
                    if (ev.filter == c_event.EVFILT_READ) self.onPeerReadable(p);
                    if (ev.filter == c_event.EVFILT_WRITE) self.onPeerWritable(p);
                }
            }

            self.timerPass();
            self.reapDead();
        }

        // Clean shutdown: stop the completion worker first — its pending
        // results write the content set, so they must land BEFORE the
        // final checkpoint.  close(kick_wr) = persistent EV_EOF: the worker
        // drains remaining jobs and exits.
        log(.info, "shutting down: completion worker drain, checkpoint", .{});
        posix.close(self.comp.kick_wr);
        self.comp.kick_wr = -1;
        if (self.comp_thread) |th| {
            th.join();
            self.comp_thread = null;
        }
        self.drainCompletions();
        self.cs.checkpoint(self.jr.high_seq) catch {};
        self.cs.snapshot() catch {};
        events.delRoot(self.dev_fd, self.cfg.replicated_path) catch {};
        if (self.ctl_fd >= 0) {
            posix.close(self.ctl_fd);
            std.fs.cwd().deleteFile(ctl.sock_path) catch {};
            self.ctl_fd = -1;
        }
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
        // Completions BEFORE kernel events: the install result updates the
        // content set so the install's own ATTRIB shadow event (which the
        // echo marker may already have consumed once) still finds the
        // record in place and gets absorbed instead of re-announced.
        self.drainCompletions();
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
        // Gap #11 selective filtering: configured op classes drop here,
        // before path resolution.  high_seq still advances — the events
        // ARE consumed (deliberately dropped) — so the ring checkpoint
        // doesn't pin the drain window on them.
        if ((self.cfg.events_drop & events.opBit(op)) != 0) {
            if (bev.seq > self.jr.high_seq) self.jr.high_seq = bev.seq;
            return;
        }
        const name = bev.nameSlice();
        var pathbuf: [4096]u8 = undefined;
        var rel: []const u8 = undefined;
        if (name.len > 0) {
            // Named event: resolve parent dir + last component.
            const dir = self.cs.dirPath(bev.fsid, bev.dir_fileid) orelse {
                // Directory unknown to us (created while down, or index
                // gap): the scan floor recovers it.
                self.need_rescan = true;
                return;
            };
            rel = if (dir.len == 0)
                std.fmt.bufPrint(&pathbuf, "{s}", .{name}) catch return
            else
                std.fmt.bufPrint(&pathbuf, "{s}/{s}", .{ dir, name }) catch return;
            // Learn the subject's identity: later self events (MODIFY/
            // ATTRIB) arrive NAMELESS and resolve through the id index.
            switch (op) {
                .create, .attrib, .move_to, .modify => self.cs.learnId(bev.fsid, bev.fileid, bev.gen, rel) catch {},
                else => {},
            }
        } else {
            // Nameless self event: resolve the subject by identity.  A
            // nonzero gen mismatch = inode reuse = we don't know this
            // file — scan floor.
            rel = self.cs.idPath(bev.fsid, bev.fileid, bev.gen) orelse {
                self.need_rescan = true;
                return;
            };
            if (rel.len == 0) return; // the root itself: nothing to do
            if (rel.len > pathbuf.len) return;
            @memcpy(pathbuf[0..rel.len], rel);
            rel = pathbuf[0..rel.len];
        }
        // Feed visibility (the tap regression suite greps this line).
        log(.info, "seq={d} op={s} fsid={x} dir={d} file={d} gen={d} cookie={x} {s}{s}", .{
            bev.seq,
            events.opName(bev.op),
            bev.fsid,
            bev.dir_fileid,
            bev.fileid,
            bev.gen,
            bev.cookie,
            if (name.len > 0) name else rel,
            if (bev.isDir()) " (dir)" else "",
        });

        // Self-echo suppression (rule 6): swallow our own install/rename
        // events, but ONLY if the file still matches what we installed.
        if (self.jr.peekEcho(rel)) |echo| {
            const swallowed = switch (echo.kind) {
                .install => blk: {
                    // Identity-marked echo (async completion): the event's
                    // subject must BE the staged file — O(1), never re-hashes
                    // a big install on the core loop.
                    if (echo.fileid != 0)
                        break :blk bev.fileid == echo.fileid and
                            (echo.gen == 0 or bev.gen == 0 or bev.gen == echo.gen);
                    break :blk self.verifyInstallEcho(rel, echo);
                },
                .move_from => blk: {
                    const abs = self.inst.absPath(rel) catch break :blk false;
                    defer self.alloc.free(abs);
                    _ = installer.statPath(abs) catch break :blk true; // gone: our rename
                    break :blk false;
                },
            };
            if (swallowed) {
                // Identity-marked install echoes persist until onInstalled
                // clears them: one install emits TWO events (MOVE_TO +
                // ATTRIB) and both must swallow.  A delete matching the
                // identity closes the window instead: the subject is dead
                // (a superseded install's revert), nothing more can come.
                if (echo.fileid == 0 or op == .delete) self.jr.clearEcho(rel);
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
        // Deletes forget the subject mapping.  Renames keep it: the
        // MOVE_TO half's learnId remaps fileid -> new path.
        if (op == .delete)
            self.cs.dropId(bev.fsid, bev.fileid);
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
            // Dirs: size/mtime change constantly as children come and go —
            // content identity for a dir is "exists + mode".  Files: full
            // (sha, size, mode) compare — ATTRIB events drive metadata-only
            // announces (mode is replicated, uid/gid are not).
            const unchanged = rec.state == .live and rec.is_dir == is_dir and
                if (is_dir)
                    rec.mode == @as(u16, @intCast(@as(u32, @intCast(st.mode)) & 0o7777))
                else
                    std.mem.eql(u8, &rec.sha256, &sha) and
                        rec.size == @as(u64, @intCast(@max(st.size, 0))) and
                        rec.mode == @as(u16, @intCast(@as(u32, @intCast(st.mode)) & 0o7777));
            if (unchanged) {
                // Spurious event (attrib-only or echo we didn't mark):
                // refresh identity silently, announce nothing.
                var r = rec.*;
                r.id = .{ .fsid = self.tree_fsid, .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
                r.mtime_sec = @intCast(st.mtim.sec);
                r.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
                r.mode = @intCast(@as(u32, @intCast(st.mode)) & 0o7777);
                self.cs.upsert(e.path, r) catch {};
                return;
            }
        }

        const ver = self.cs.nextVersion();
        const rec = contentset.Record{
            .id = .{ .fsid = self.tree_fsid, .fileid = @intCast(st.ino), .gen = @intCast(st.gen) },
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

        // The winning local change aborts a losing in-flight fetch
        // (saves the transfer; a completing fetch is the worker's — the
        // pre-landing discard and the superseded-revert cover it).
        if (self.incoming.get(e.path)) |inf| {
            const iv = inf.ver;
            const completing = inf.completing;
            if (!completing) switch (contentset.relate(ver, iv)) {
                .newer, .conflict_incoming_wins => {
                    log(.info, "aborting losing fetch {s} v=({x},{d})", .{ e.path, iv.origin, iv.seq });
                    self.inst.abortFetch(e.path);
                    if (self.incoming.fetchRemove(e.path)) |kv| self.alloc.free(kv.key);
                },
                else => {},
            };
        }
    }

    fn processDelete(self: *Daemon, e: *journal.Entry) void {
        const rec = self.cs.lookup(e.path) orelse return;
        if (rec.state == .deleted) return;
        // Gap #17 mass-delete guard (guard.zig): covers BOTH the live
        // event feed and the rescan floor (scan deletes are journaled
        // through this same point).  Peer tombstones never pass here.
        // Directory deletes are weighted by live-descendant count: a dir
        // tombstone cascades to the whole subtree on receivers.
        const weight: u64 = if (rec.is_dir) 1 + self.cs.liveDescendants(e.path) else 1;
        switch (self.guard.gate(peer_mod.nowMs(), weight)) {
            .allow => {},
            .check_live => if (!self.guard.checkLive(self.cs.liveCount())) {
                log(.err, "MASS-DELETE GUARD TRIPPED: {d} local deletes inside {d}ms — local tombstones suppressed until 'brfsctl massdelete resume'", .{ self.guard.count, guard_mod.window_ms });
                return;
            },
            .suppress => return,
        }
        const ver = self.cs.nextVersion();
        var r = rec.*;
        r.state = .deleted;
        r.ver = ver;
        const is_dir = r.is_dir;
        // NOTE: rec is a pointer into the hashmap's internal storage;
        // upsert may resize the map (even for existing keys getOrPut
        // checks load factor first), so rec is potentially dangling after
        // this call.  Use the stack-local copy `r` for any field access.
        self.cs.upsert(e.path, r) catch return;
        self.broadcast(.{ .tombstone = .{ .ver = ver, .is_dir = is_dir, .path = e.path } });
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
        // Copy the record by value BEFORE any upsert: rec is a pointer
        // into the hashmap's internal storage and may be invalidated by
        // upsert (getOrPut can resize even for existing keys).
        var dst = rec.*;
        dst.ver = ver;
        dst.state = .live;
        const is_dir = dst.is_dir;
        // Refresh identity from the destination.
        if (self.inst.absPath(r.to)) |abs| {
            defer self.alloc.free(abs);
            if (installer.statPath(abs)) |st| {
                dst.id = .{ .fsid = self.tree_fsid, .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
                dst.size = @intCast(@max(st.size, 0));
                dst.mtime_sec = @intCast(st.mtim.sec);
                dst.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
                dst.mode = @intCast(@as(u32, @intCast(st.mode)) & 0o7777);
            } else |_| {}
        } else |_| {}
        self.cs.upsert(r.to, dst) catch return;
        // rec is now potentially dangling — use dst (stack copy) only.
        var tomb = dst;
        tomb.state = .deleted;
        tomb.ver = ver;
        self.cs.upsert(r.from, tomb) catch return;

        self.move_cookie +%= 1;
        const cookie = self.move_cookie;
        self.broadcast(.{ .move_from = .{ .ver = ver, .is_dir = is_dir, .cookie = cookie, .path = r.from } });
        self.broadcast(.{ .move_to = .{ .ver = ver, .is_dir = is_dir, .cookie = cookie, .path = r.to } });
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
            if (self.tls_ctx) |ctx| {
                p.startTls(ctx) catch {
                    self.dropPeer(p, peer_mod.nowMs(), "TLS init failed (inbound)");
                    return;
                };
            }
            self.registerPeerFd(p);
            if (p.state != .tls_handshake)
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
            self.stageChange(@intCast(p.fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, p);
            if (self.tls_ctx) |ctx| {
                p.startTls(ctx) catch {
                    self.dropPeer(p, peer_mod.nowMs(), "TLS init failed (outbound)");
                    return;
                };
                self.driveTlsHandshake(p);
            } else {
                self.sendHello(p);
            }
            return;
        }
        if (p.state == .tls_handshake) {
            self.driveTlsHandshake(p);
            return;
        }
        p.writeReady() catch {
            self.dropPeer(p, peer_mod.nowMs(), "write failed");
        };
    }

    fn onPeerReadable(self: *Daemon, p: *Peer) void {
        if (p.state == .connecting) return; // completion is the WRITE event
        if (p.state == .tls_handshake) {
            self.driveTlsHandshake(p);
            return;
        }
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

    /// Queue + optimistically flush.  CRITICAL kqueue semantics: on an
    /// idle, fully-writable socket, re-adding an already-armed EVFILT_WRITE
    /// filter does NOT re-fire (no space-available transition happens), so
    /// frames would sit in wbuf indefinitely.  Always attempt the write
    /// synchronously; the armed WRITE filter is only the backpressure
    /// continuation for when the socket buffer is genuinely full.
    fn pushTo(self: *Daemon, p: *Peer, msg: protocol.Message) void {
        p.send(msg) catch {
            self.dropPeer(p, peer_mod.nowMs(), "send queue saturated");
            return;
        };
        self.flushPeer(p);
    }

    fn flushPeer(self: *Daemon, p: *Peer) void {
        if (p.state == .connecting or p.state == .tls_handshake or p.state == .closed) return;
        p.writeReady() catch {
            self.dropPeer(p, peer_mod.nowMs(), "write failed");
            return;
        };
        if (p.wantsWrite())
            self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
    }

    /// Drive the TLS handshake forward.  Called from onPeerReadable and
    /// onPeerWritable when the peer is in .tls_handshake state.  On
    /// completion, sends HELLO.  On want_read/want_write, re-arms the
    /// appropriate kqueue filter (already done via EV_CLEAR on the fd).
    fn driveTlsHandshake(self: *Daemon, p: *Peer) void {
        const result = p.tlsHandshake() catch {
            self.dropPeer(p, peer_mod.nowMs(), "TLS handshake failed");
            return;
        };
        switch (result) {
            .complete => {
                log(.info, "TLS handshake complete with {s}", .{peerName(p)});
                self.sendHello(p);
            },
            .want_read => {
                // EV_CLEAR on the READ filter is already armed.
            },
            .want_write => {
                self.stageChange(@intCast(p.fd), c_event.EVFILT_WRITE, c_event.EV_ADD | c_event.EV_CLEAR, p);
            },
        }
    }

    fn sendHello(self: *Daemon, p: *Peer) void {
        var nonce: [protocol.nonce_len]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        self.pushTo(p, .{ .hello = .{
            .proto = protocol.protocol_version,
            .node_id = self.cfg.node_id,
            .psk = self.psk,
            .nonce = nonce,
        } });
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
                // Only act on a NACK for the CURRENT attempt: a stale NACK
                // from a superseded fetch must not kill a fresh one, and a
                // completing fetch belongs to the worker.
                const cur = self.incoming.get(m.path) orelse return;
                if (!cur.ver.eql(m.ver) or cur.completing) return;
                if (m.code == nack_missing) {
                    // Gap #10 source-selection: the announce source doesn't
                    // hold the content — fall back to another ready peer,
                    // keeping the staged bytes (same version; the final
                    // hash verifies the assembly).
                    if (self.pickAlternateSource(m.path)) |alt| {
                        const off = self.inst.fetchOffset(m.path);
                        log(.info, "fetch {s} v=({x},{d}): source fallback {s} -> {s} at offset {d}", .{
                            m.path, m.ver.origin, m.ver.seq, peerName(p), peerName(alt), off,
                        });
                        if (self.incoming.getPtr(m.path)) |mp| mp.deadline_ms = now + fetch_timeout_ms;
                        self.requestChunk(alt, m.path, m.ver, off);
                        return;
                    }
                }
                if (m.code == nack_missing or m.code == nack_stale) {
                    self.inst.abortFetch(m.path);
                    if (self.incoming.fetchRemove(m.path)) |kv| self.alloc.free(kv.key);
                }
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
        var i: usize = 0;
        while (i < self.peers.items.len) : (i += 1) {
            const p = self.peers.items[i];
            if (p.state != .ready) continue;
            const before = p;
            self.pushTo(p, msg);
            // pushTo may dropPeer (swapRemove): re-examine slot i.
            if (before.state == .closed and i < self.peers.items.len and self.peers.items[i] != before)
                i -%= 1;
        }
    }

    // ---- replication message handlers ----

    fn onAnnounce(self: *Daemon, p: *Peer, m: protocol.Announce) void {
        if (p.state != .ready) return;
        log(.info, "recv announce {s} v=({x},{d}) size={d} from {s}", .{
            m.path, m.ver.origin, m.ver.seq, m.size, peerName(p),
        });
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
        // An in-flight or completing fetch is the effective stored version:
        // an announce that would LOSE to it must not restart the fetch —
        // async completion reopened the same-path ordering the synchronous
        // complete() gave for free (V1 installing while V2 is announced).
        if (self.incoming.get(m.path)) |inc| {
            switch (contentset.relate(m.ver, inc.ver)) {
                .same, .older, .conflict_stored_wins => return,
                else => {},
            }
        }
        const stored = self.cs.lookup(m.path);
        if (stored) |rec| {
            switch (contentset.relate(m.ver, rec.ver)) {
                .same, .older => return,
                .conflict_stored_wins => return, // we win; peer converges via our ANNOUNCE
                .newer => {},
                .conflict_incoming_wins => {
                    // Don't quarantine eagerly: a divergent local file is
                    // moved aside atomically at install time (installer.
                    // complete), which keeps the kernel from seeing a
                    // spurious delete/rename of the loser.
                    //
                    // Gap #9 (LOCKED): a stored TOMBSTONE that loses here
                    // resurrects the path — the offline modify M > tombstone
                    // N case falls through to the fetch/install below, and
                    // the deleting side has no local copy to quarantine.
                    if (rec.state == .deleted)
                        log(.info, "resurrect {s}: peer {s} v=({x},{d}) wins over tombstone", .{
                            m.path, peerName(p), m.ver.origin, m.ver.seq,
                        })
                    else
                        log(.info, "conflict {s}: peer {s} v=({x},{d}) wins over local", .{
                            m.path, peerName(p), m.ver.origin, m.ver.seq,
                        });
                },
            }
        }
        if (m.is_dir) {
            const abs = self.inst.absPath(m.path) catch return;
            defer self.alloc.free(abs);
            std.fs.cwd().makePath(abs) catch {};
            installer.setMeta(abs, m.mode, m.mtime_sec, m.mtime_nsec);
            self.upsertFromWire(m.path, m.ver, true, m.mode, 0, m.mtime_sec, m.mtime_nsec, m.sha256);
            return;
        }
        // Metadata-only announce (ATTRIB path): identical content needs no
        // transfer — just apply mode/mtime and adopt the version.
        if (stored) |rec| {
            if (rec.state == .live and !rec.is_dir and
                std.mem.eql(u8, &rec.sha256, &m.sha256) and rec.size == m.size)
            {
                const abs = self.inst.absPath(m.path) catch return;
                defer self.alloc.free(abs);
                installer.setMeta(abs, m.mode, m.mtime_sec, m.mtime_nsec);
                self.upsertFromWire(m.path, m.ver, false, m.mode, m.size, m.mtime_sec, m.mtime_nsec, m.sha256);
                return;
            }
        }
        self.startFetch(p, m.path, m.ver, m.size, m.sha256, m.mode, m.mtime_sec, m.mtime_nsec);
    }

    fn startFetch(self: *Daemon, p: *Peer, path: []const u8, ver: Version, size: u64, sha: [32]u8, mode: u16, mtime_sec: i64, mtime_nsec: u32) void {
        var meta = Incoming{ .ver = ver, .size = size, .sha256 = sha, .mode = mode, .mtime_sec = mtime_sec, .mtime_nsec = mtime_nsec, .deadline_ms = peer_mod.nowMs() + fetch_timeout_ms };
        // Gap #10: the announce/resync source is always the FIRST choice.
        if (p.node_id) |nid| meta.markTried(nid);
        const gop = self.incoming.getOrPut(path) catch return;
        if (!gop.found_existing)
            gop.key_ptr.* = self.alloc.dupe(u8, path) catch return;
        gop.value_ptr.* = meta;

        // A fetch already in flight for this path is stale by definition
        // (this announce carries the version we actually want now).
        if (self.inst.fetchInProgress(path))
            self.inst.abortFetch(path);
        self.inst.beginFetch(path, meta) catch |err| {
            log(.warn, "beginFetch {s}: {s}", .{ path, @errorName(err) });
            return;
        };
        self.requestChunk(p, path, ver, 0);
    }

    /// Receiver-driven pull: exactly one chunk in flight per fetch.
    fn requestChunk(self: *Daemon, p: *Peer, path: []const u8, ver: Version, offset: u64) void {
        self.pushTo(p, .{ .fetch_req = .{ .ver = ver, .offset = offset, .len = installer.chunk_size, .path = path } });
    }

    /// Gap #10: pick a fallback source for a fetch whose current source
    /// NACKed with nack_missing.  Any converged peer can serve (full mesh,
    /// no relaying); the tried-list prevents loops.  null = every ready
    /// peer already tried (caller falls back to the abort/stall path).
    fn pickAlternateSource(self: *Daemon, path: []const u8) ?*Peer {
        const inc = self.incoming.getPtr(path) orelse return null;
        for (self.peers.items) |q| {
            if (q.state != .ready) continue;
            const nid = q.node_id orelse continue;
            if (inc.wasTried(nid)) continue;
            inc.markTried(nid);
            return q;
        }
        return null;
    }

    const nack_stale: u16 = 1;
    const nack_missing: u16 = 2;

    fn onFetchReq(self: *Daemon, p: *Peer, m: protocol.FetchReq) void {
        if (p.state != .ready) return;
        const rec = self.cs.lookup(m.path) orelse {
            log(.info, "fetch_req {s} v=({x},{d}) off={d} from {s}: NACK missing (no record)", .{
                m.path, m.ver.origin, m.ver.seq, m.offset, peerName(p),
            });
            self.sendNack(p, m.path, m.ver, nack_missing);
            return;
        };
        if (rec.state != .live or rec.is_dir) {
            log(.info, "fetch_req {s} v=({x},{d}) off={d} from {s}: NACK missing (state)", .{
                m.path, m.ver.origin, m.ver.seq, m.offset, peerName(p),
            });
            self.sendNack(p, m.path, m.ver, nack_missing);
            return;
        }
        if (!rec.ver.eql(m.ver)) {
            // Stale request: the requester will re-fetch from the fresh
            // ANNOUNCE we proactively emit.
            self.sendNack(p, m.path, m.ver, nack_stale);
            self.announceRecord(p, m.path, rec);
            return;
        }
        if (m.offset > rec.size) {
            self.sendNack(p, m.path, m.ver, nack_stale);
            return;
        }
        // Meta first: the unpaired-MOVE_TO fetch path on the receiver has
        // no ANNOUNCE yet; in the normal flow this is an idempotent no-op.
        // (Only before the FIRST chunk — per-chunk prefaces waste frames.)
        if (m.offset == 0) self.announceRecord(p, m.path, rec);

        // Serve exactly one requested chunk (receiver-driven pacing).
        const abs = self.inst.absPath(m.path) catch return;
        defer self.alloc.free(abs);
        const fd = posix.open(abs, .{ .ACCMODE = .RDONLY }, 0) catch {
            self.sendNack(p, m.path, m.ver, nack_missing);
            return;
        };
        defer posix.close(fd);
        const want: usize = @intCast(@min(@as(u64, m.len), rec.size - m.offset));
        var buf: [installer.chunk_size]u8 = undefined;
        var data: []const u8 = &.{};
        if (want > 0) {
            const n = posix.pread(fd, buf[0..want], @intCast(m.offset)) catch return;
            data = buf[0..n];
        }
        log(.info, "fetch_req {s} v=({x},{d}) off={d} from {s}: serving {d} bytes", .{
            m.path, m.ver.origin, m.ver.seq, m.offset, peerName(p), data.len,
        });
        self.pushTo(p, .{ .fetch_data = .{ .ver = m.ver, .offset = m.offset, .path = m.path, .data = data } });
    }

    fn announceRecord(self: *Daemon, p: *Peer, path: []const u8, rec: *const contentset.Record) void {
        self.pushTo(p, .{ .announce = .{
            .ver = rec.ver,
            .is_dir = false,
            .mode = rec.mode,
            .size = rec.size,
            .mtime_sec = rec.mtime_sec,
            .mtime_nsec = rec.mtime_nsec,
            .path = path,
            .sha256 = rec.sha256,
        } });
    }

    fn onFetchData(self: *Daemon, p: *Peer, m: protocol.FetchData) void {
        if (p.state != .ready) return;
        self.inst.writeChunk(m.path, m.ver, m.offset, m.data) catch |err| {
            log(.warn, "writeChunk {s}: {s}", .{ m.path, @errorName(err) });
            self.inst.abortFetch(m.path);
            if (self.incoming.fetchRemove(m.path)) |kv| self.alloc.free(kv.key);
            return;
        };
        if (!self.inst.fetchComplete(m.path)) {
            // Progress: push the stall deadline out (the timeout is a
            // STALL detector, not a transfer deadline).
            if (self.incoming.getPtr(m.path)) |meta|
                meta.deadline_ms = peer_mod.nowMs() + fetch_timeout_ms;
            if (m.data.len == 0) {
                // Zero progress: the sender's copy shrank under us (stale
                // size).  Abort; the sender's next ANNOUNCE re-drives.
                log(.warn, "fetch {s}: short file at offset {d}, aborting", .{ m.path, m.offset });
                self.inst.abortFetch(m.path);
                if (self.incoming.fetchRemove(m.path)) |kv| self.alloc.free(kv.key);
                return;
            }
            self.requestChunk(p, m.path, m.ver, self.inst.fetchOffset(m.path));
            return;
        }

        const meta = self.incoming.get(m.path) orelse {
            self.inst.abortFetch(m.path);
            return;
        };
        var job = self.inst.beginComplete(m.path) catch |err| {
            log(.warn, "install {s} failed: {s}", .{ m.path, @errorName(err) });
            if (self.incoming.fetchRemove(m.path)) |kv| self.alloc.free(kv.key);
            // protocol.md: a hash mismatch REQUEUES (bounded — the file
            // may be actively changing on the sender; each retry re-reads).
            if (err == error.HashMismatch and meta.retries < 3) {
                log(.info, "requeue fetch {s} (retry {d})", .{ m.path, meta.retries + 1 });
                self.startFetch(p, m.path, meta.ver, meta.size, meta.sha256, meta.mode, meta.mtime_sec, meta.mtime_nsec);
                if (self.incoming.getPtr(m.path)) |e| e.retries = meta.retries + 1;
            }
            return;
        };
        // Never land a losing install (T5 cascade, rig-proven 2026-08-26):
        // a local upsert that beat this fetch while it was transferring
        // would have the worker quarantine the WINNER's content and the
        // superseded-install revert then lose the file on disk entirely.
        // Discard the staging file instead: the tree is never touched.
        if (self.cs.lookup(m.path)) |rec| {
            switch (contentset.relate(m.ver, rec.ver)) {
                .same, .older, .conflict_stored_wins => {
                    log(.info, "install {s} v=({x},{d}) lost the race before landing; discarding", .{ m.path, m.ver.origin, m.ver.seq });
                    self.inst.discardComplete(&job);
                    self.alloc.free(job.path);
                    self.dropIncoming(m.path, m.ver);
                    return;
                },
                .newer, .conflict_incoming_wins => {},
            }
        }
        // Identity echo marker BEFORE the worker's rename: the resulting
        // kernel events (MOVE_TO + ATTRIB) must find it (rule 6), and the
        // fileid/gen swallow never re-hashes a big install on this loop.
        self.jr.noteEchoFile(m.path, job.sha256, job.size, job.fileid, job.gen) catch {};
        // Resolve the install's own nameless self events from the first
        // moment they can arrive (they may beat the completion result).
        self.cs.learnId(self.tree_fsid, job.fileid, job.gen, m.path) catch {};
        if (p.node_id) |nid| job.ack_peer = self.alloc.dupe(u8, nid) catch null;
        if (self.incoming.getPtr(m.path)) |e| e.completing = true;
        self.comp.submit(job);
        log(.info, "install queued {s} v=({x},{d}) size={d}", .{ m.path, m.ver.origin, m.ver.seq, meta.size });
    }

    /// Completion worker -> core: an install finished (or failed).
    fn onInstalled(self: *Daemon, res: *installer.CompleteResult) void {
        const path = res.job.path;
        defer self.alloc.free(path);
        defer if (res.job.ack_peer) |ap| self.alloc.free(ap);
        defer if (res.job.quarantined) |q| self.alloc.free(q);

        if (res.err) |err| {
            log(.warn, "install {s} failed: {s}", .{ path, @errorName(err) });
            self.cs.dropId(self.tree_fsid, res.job.fileid);
            self.jr.clearEcho(path);
            self.dropIncoming(path, res.job.ver);
            return;
        }

        // A newer tombstone/record may have landed while the worker was
        // fsyncing: the set is the authority — undo the on-disk install.
        if (self.cs.lookup(path)) |rec| {
            switch (contentset.relate(res.job.ver, rec.ver)) {
                .same => {
                    // Idempotent duplicate; already recorded.
                    self.jr.clearEcho(path);
                    self.dropIncoming(path, res.job.ver);
                    return;
                },
                .older, .conflict_stored_wins => {
                    log(.info, "install {s} v=({x},{d}) superseded mid-flight; reverting", .{
                        path, res.job.ver.origin, res.job.ver.seq,
                    });
                    // NO clearEcho / NO marker replacement: the install's
                    // identity marker (set pre-submit) covers our revert
                    // too — the MOVE_TO + ATTRIB of the landing AND the
                    // DELETE of the revert all carry the loser's fileid
                    // (a delete-swallow closes the marker).  Keep the
                    // id-index mapping so the late nameless ATTRIB still
                    // resolves to the path and finds the marker.
                    self.inst.tombstone(path, false) catch {};
                    // Restore the divergent copy the worker quarantined:
                    // it is the winning version's content.  Without the
                    // restore the winner's record stays live with no file
                    // on disk and the next rescan tombstones it mesh-wide
                    // (T5 cascade).  No echo marker for the restore: the
                    // journal's unchanged-check absorbs it (or it is a
                    // genuinely newer local edit, which MUST announce).
                    self.restoreQuarantined(path, res.job.quarantined);
                    self.dropIncoming(path, res.job.ver);
                    return;
                },
                .newer, .conflict_incoming_wins => {},
            }
        }

        self.upsertFromWire(path, res.job.ver, false, res.job.mode, res.job.size, res.job.mtime_sec, res.job.mtime_nsec, res.job.sha256);
        // ACK the serving node if still connected (advisory; a missing ACK
        // is a no-op on the sender).
        if (res.job.ack_peer) |nid| {
            for (self.peers.items) |q| {
                if (q.state == .ready and q.node_id != null and
                    std.mem.eql(u8, q.node_id.?, nid))
                {
                    self.pushTo(q, .{ .fetch_ack = .{ .ver = res.job.ver, .path = path, .sha256 = res.job.sha256 } });
                    break;
                }
            }
        }
        // The install's echo window closes here (both kernel events of the
        // install had their chance to swallow on the identity marker).
        self.jr.clearEcho(path);
        self.dropIncoming(path, res.job.ver);
        log(.info, "installed {s} v=({x},{d}) size={d}", .{ path, res.job.ver.origin, res.job.ver.seq, res.job.size });
    }

    /// Rename a quarantined divergent copy back into the tree (revert of
    /// a superseded install).  No echo marker: the restored content either
    /// matches the winning stored record byte-for-byte (the journal's
    /// unchanged-check absorbs the events) or it is a genuinely newer
    /// local edit, which MUST announce forward.
    fn restoreQuarantined(self: *Daemon, path: []const u8, qname: ?[]const u8) void {
        const qn = qname orelse return;
        const src = std.fs.path.join(self.alloc, &.{ self.inst.conflicts, qn }) catch return;
        defer self.alloc.free(src);
        const dst = self.inst.absPath(path) catch return;
        defer self.alloc.free(dst);
        posix.rename(src, dst) catch |err| {
            log(.warn, "restore {s} from quarantine failed: {s}", .{ path, @errorName(err) });
        };
    }

    /// Drop the incoming entry IF it still belongs to this version (a newer
    /// fetch may have replaced it while the worker installed the old one).
    fn dropIncoming(self: *Daemon, path: []const u8, ver: Version) void {
        if (self.incoming.getPtr(path)) |e| {
            if (!e.ver.eql(ver)) return;
        }
        if (self.incoming.fetchRemove(path)) |kv| self.alloc.free(kv.key);
    }

    fn drainCompletions(self: *Daemon) void {
        var results: std.ArrayList(installer.CompleteResult) = .empty;
        defer results.deinit(self.alloc);
        self.comp.takeResults(&results);
        for (results.items) |*res| self.onInstalled(res);
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
        var quarantine_loser = false;
        if (self.cs.lookup(m.path)) |rec| {
            switch (contentset.relate(m.ver, rec.ver)) {
                .same, .older, .conflict_stored_wins => return,
                .newer => {},
                .conflict_incoming_wins => {
                    // Loser content is preserved (DFSR ConflictAndDeleted).
                    quarantine_loser = true;
                },
            }
        }
        // T19 race: a same-origin tombstone applies cleanly per the stored
        // record, but a local edit can still sit in the journal's debounce
        // window (never committed a version).  Without this the tombstone
        // deletes the edited file silently; with it, the in-flight edit is
        // quarantined before the delete (rig-proven 2026-08-30).  Rare
        // false positive (attrib-only touch quarantines identical content)
        // is acceptable — conflicts/ is operator-prunable.
        if (!quarantine_loser and !m.is_dir and self.jr.hasPending(m.path))
            quarantine_loser = true;
        // Echo suppression BEFORE the fs mutations: the deletes we perform
        // (and a quarantine move) must not re-enter the journal as local
        // changes.  A dir tombstone removes the subtree: mark every live
        // descendant we know about.
        self.markEchoSubtree(m.path, m.is_dir);
        if (quarantine_loser) {
            if (self.inst.quarantine(m.path) catch null) |qn|
                self.alloc.free(qn); // informational; nothing to restore here
        }
        self.inst.tombstone(m.path, m.is_dir) catch |err| {
            log(.warn, "tombstone {s}: {s}", .{ m.path, @errorName(err) });
        };
        var rec = contentset.Record{ .ver = m.ver, .is_dir = m.is_dir, .state = .deleted };
        if (self.cs.lookup(m.path)) |old| rec.id = old.id;
        self.cs.upsert(m.path, rec) catch {};
        // Tombstone the subtree records too (same version — the sender's
        // per-file tombstones relate as same/older and no-op).
        if (m.is_dir) self.tombstoneSubtree(m.path, m.ver);
        log(.info, "applied tombstone {s} v=({x},{d})", .{ m.path, m.ver.origin, m.ver.seq });
    }

    /// Echo-mark a path and (for dirs) every live descendant in the set.
    fn markEchoSubtree(self: *Daemon, path: []const u8, is_dir: bool) void {
        self.jr.noteEcho(path, .move_from, [_]u8{0} ** 32, 0) catch {};
        if (!is_dir) return;
        var it = self.cs.map.iterator();
        while (it.next()) |e| {
            const p2 = e.key_ptr.*;
            if (e.value_ptr.state != .live) continue;
            if (p2.len > path.len and std.mem.startsWith(u8, p2, path) and p2[path.len] == '/')
                self.jr.noteEcho(p2, .move_from, [_]u8{0} ** 32, 0) catch {};
        }
    }

    /// Tombstone all live descendants of a dir (applied dir delete).
    fn tombstoneSubtree(self: *Daemon, path: []const u8, ver: Version) void {
        var descendants: std.ArrayList(struct { p: []const u8, is_dir: bool, id: contentset.Id }) = .empty;
        defer descendants.deinit(self.alloc);
        var it = self.cs.map.iterator();
        while (it.next()) |e| {
            const p2 = e.key_ptr.*;
            if (e.value_ptr.state != .live) continue;
            if (p2.len > path.len and std.mem.startsWith(u8, p2, path) and p2[path.len] == '/')
                descendants.append(self.alloc, .{ .p = p2, .is_dir = e.value_ptr.is_dir, .id = e.value_ptr.id }) catch return;
        }
        for (descendants.items) |d| {
            self.cs.upsert(d.p, .{ .id = d.id, .ver = ver, .is_dir = d.is_dir, .state = .deleted }) catch {};
        }
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

        // Copy by value BEFORE any upsert: from_rec is a pointer into the
        // hashmap's internal storage and may be invalidated if the map grows.
        var dst = from_rec.?.*;
        dst.ver = m.ver;
        dst.state = .live;
        if (installer.statPath(abs_to)) |st| {
            dst.id = .{ .fsid = self.tree_fsid, .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
            dst.size = @intCast(@max(st.size, 0));
            dst.mtime_sec = @intCast(st.mtim.sec);
            dst.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
        } else |_| {}
        self.cs.upsert(m.path, dst) catch {};
        // from_rec is now potentially dangling — use dst (stack copy).
        var tomb = dst;
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
        self.pushTo(p, .{ .nack = .{ .ver = ver, .code = code, .path = path } });
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
                rec.id = .{ .fsid = self.tree_fsid, .fileid = @intCast(st.ino), .gen = @intCast(st.gen) };
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
        // Full-record pull (rig-proven 2026-08-28): a conn drop mid-
        // announce-burst loses queued frames, and the per-origin-MAX
        // version vector cannot express the resulting hole — vector-diff
        // resync reported "0 entries" while the requester was missing 934
        // records (t-ringoverflow divergence).  An empty vector asks the
        // peer to stream ALL records; entryAction idempotently ignores
        // what we already hold and fetches the holes.  Reconnects are
        // rare and trees are POC-scale; Phase 3's durable journal
        // restores efficient diffing.
        self.pushTo(p, .{ .resync_req = .{ .vector = undefined, .count = 0 } });
    }

    /// Gap #7 ack horizon: record the member's announced vector.
    fn noteMemberVector(self: *Daemon, node_id: []const u8, req: protocol.ResyncReq) void {
        const h = std.hash.Fnv1a_64.hash(node_id);
        var slot: ?*resync.MemberVector = null;
        for (&self.member_vectors) |*mv| {
            if (mv.used and mv.node_hash == h) {
                slot = mv;
                break;
            }
            if (!mv.used and slot == null) slot = mv;
        }
        const mv = slot orelse return; // table full: TTL-only GC for this member
        mv.used = true;
        mv.node_hash = h;
        for (req.vector[0..req.count]) |ve| mv.record(ve.origin, ve.max_seq);
    }

    /// Gap #7 horizon predicate: true when every configured peer has
    /// reported a vector AND every reported vector covers ver.  A member
    /// never heard from keeps TTL as the only retention bound (a wiped
    /// member rejoining later resurrects — accepted; that is the TTL
    /// window's documented failure mode).
    fn ackCovers(ctx: *const anyopaque, ver: Version) bool {
        const self: *const Daemon = @ptrCast(@alignCast(ctx));
        var held: u64 = 0;
        for (&self.member_vectors) |*mv| {
            if (!mv.used) continue;
            held += 1;
            if (!mv.covers(ver)) return false;
        }
        return held >= self.cfg.num_peers;
    }

    fn onResyncReq(self: *Daemon, p: *Peer, m: protocol.ResyncReq) void {
        if (p.state != .ready) return;
        // Gap #7: the requester's vector doubles as its ack horizon proof.
        if (p.node_id) |nid| self.noteMemberVector(nid, m);
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
        self.pushTo(p, .{ .resync_done = count });
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
                // An in-flight or completing fetch already covers this
                // entry (the same record streams from every ready peer on
                // a multi-peer RESYNC — without this, C's pull from A and B
                // double-fetched and the two completion jobs shared one
                // staging path: the second rename found it gone).
                if (self.incoming.get(m.path)) |inc| {
                    switch (contentset.relate(m.ver, inc.ver)) {
                        .same, .older, .conflict_stored_wins => return,
                        else => {},
                    }
                }
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
            if (self.fs_frozen) return; // gap #16: no scan against the wrong fs
            // Post-join scan: local-only files (never in the group) join
            // the mesh as fresh local content.
            const stats = resync.scan(self.alloc, self.cfg.replicated_path, &self.cs, &self.jr, peer_mod.nowMs(), self.scanInflight()) catch return;
            log(.info, "post-join scan: seen={d} new={d} mod={d} del={d}", .{
                stats.seen, stats.announced_new, stats.announced_modified, stats.announced_deleted,
            });
        }
    }

    // ---- periodic ----

    /// Rescan-floor in-flight guard (resync.InFlight): the fetch/install
    /// machinery owns these paths; the scan must not re-origin them.
    fn incomingContains(ctx: *const anyopaque, rel: []const u8) bool {
        const self: *const Daemon = @ptrCast(@alignCast(ctx));
        return self.incoming.contains(rel);
    }

    fn scanInflight(self: *Daemon) resync.InFlight {
        return .{ .ctx = self, .contains = incomingContains };
    }

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
                // Mesh dedup is per-PAIR: if we already hold a ready conn
                // to this node (the pair's surviving direction), stay quiet.
                if (p.known_id) |kid| {
                    var have = false;
                    for (self.peers.items) |q| {
                        if (q.state == .ready and q.node_id != null and
                            std.mem.eql(u8, q.node_id.?, kid))
                        {
                            have = true;
                            break;
                        }
                    }
                    if (have) {
                        if (p.next_retry_ms <= now) // log only at the moment we first suppress
                            log(.info, "dial to {s} suppressed: ready conn exists", .{kid});
                        p.next_retry_ms = now + peer_mod.backoff_max_ms;
                        continue;
                    }
                }
                const fd = p.dial(p.addr.?) catch {
                    p.disconnected(now);
                    continue;
                };
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
            if (!self.rootFsidOk()) {
                // Gap #16, runtime half: a forced unmount mid-run swapped
                // the path to the parent fs's mountpoint — the tree LOOKS
                // empty.  Defer (keep need_rescan set) instead of
                // tombstoning the mesh; remount restores the fsid and the
                // next pass converges automatically.
                log(.err, "watched root fsid changed (forced unmount?) — rescan deferred, tombstones frozen", .{});
                self.last_rescan_ms = now;
            } else {
                self.need_rescan = false;
                self.last_rescan_ms = now;
                const stats = resync.scan(self.alloc, self.cfg.replicated_path, &self.cs, &self.jr, now, self.scanInflight()) catch return;
                log(.info, "rescan: seen={d} new={d} mod={d} del={d}", .{
                    stats.seen, stats.announced_new, stats.announced_modified, stats.announced_deleted,
                });
            }
        }

        // Fetch timeouts: abandoned transfers are re-driven by the next
        // ANNOUNCE or resync round.
        var expired_f: std.ArrayList([]const u8) = .empty;
        defer expired_f.deinit(self.alloc);
        var iit = self.incoming.iterator();
        while (iit.next()) |e| {
            // The completion worker owns completing entries: a 200MB fsync
            // legitimately exceeds the stall window.
            if (e.value_ptr.completing) continue;
            if (e.value_ptr.deadline_ms <= now)
                expired_f.append(self.alloc, e.key_ptr.*) catch break;
        }
        var restalled = false;
        for (expired_f.items) |path| {
            log(.warn, "fetch {s} stalled (no progress {d}ms); aborting", .{ path, fetch_timeout_ms });
            self.inst.abortFetch(path);
            if (self.incoming.fetchRemove(path)) |kv| self.alloc.free(kv.key);
            restalled = true;
        }
        // Re-drive: a fresh vector pull re-fetches whatever we still lack
        // (idempotent; peers stream only what our vector doesn't cover).
        if (restalled) {
            for (self.peers.items) |p| {
                if (p.state == .ready) self.sendResyncReq(p);
            }
        }

        // Ring-seq checkpoint (USN analog resume point).
        if (now - self.last_checkpoint_ms >= checkpoint_interval_ms) {
            self.last_checkpoint_ms = now;
            self.cs.checkpoint(self.jr.high_seq) catch {};
            self.cs.flush() catch {};
        }

        // Tombstone GC (gap #7): collect when the 7-day TTL expired OR
        // every configured member's announced vector covers the tombstone
        // (the all-member-ack horizon — early collection for a healthy
        // mesh).
        if (now - self.last_gc_ms >= gc_interval_ms) {
            self.last_gc_ms = now;
            const horizon = contentset.AckHorizon{ .ctx = self, .covers = ackCovers };
            const collected = self.cs.gcTombstones(@intCast(@divFloor(now, 1000)), horizon) catch 0;
            if (collected > 0)
                log(.info, "tombstone GC: {d} collected", .{collected});
        }

        // Watch-root re-push (watch-removal flag-strip mitigation).
        // Removing the last genuine inotify watch on a directory strips
        // VIRF_INOTIFY under it (vfs_inotify.c) even when the flag was
        // ours, leaving a silent coverage gap; a kernel-side refcount is
        // infeasible (struct inotify_softc is opaque, watch removal
        // cannot be interposed).  ADDROOT is idempotent: re-resolve,
        // re-flag, re-patch.  Also re-flags the root after it was
        // renamed out of the tree and back.
        if (now - self.last_repush_ms >= repush_interval_ms) {
            self.last_repush_ms = now;
            // Gap #16: never re-push while the root resolves to the wrong
            // fs (forced unmount) — that would flag the parent fs's tree.
            if (self.rootFsidOk()) {
                events.addRoot(self.dev_fd, self.cfg.replicated_path, 0) catch |err|
                    log(.warn, "watch-root re-push failed: {s}", .{@errorName(err)});
            }
        }
    }

    /// Runtime half of the gap #16 forced-unmount guard: the CURRENT fsid
    /// of the watched root must match what we indexed at start.  UFS/ZFS
    /// fsids are mount-stable, so a remount restores the match.
    fn rootFsidOk(self: *Daemon) bool {
        if (self.fs_frozen) return false;
        const cur = installer.fsidOf(self.cfg.replicated_path) catch return false;
        return cur == self.tree_fsid;
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

    // ---- control socket (/var/run/brfsd.sock, brfsctl backend) ----

    fn onCtlAccept(self: *Daemon) void {
        // Edge-triggered (EV_CLEAR): drain the accept queue.
        while (true) {
            const cfd = ctl.accept(self.ctl_fd) catch return; // WouldBlock = drained
            self.stageChange(@intCast(cfd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, @ptrCast(&ctl_conn_tag));
        }
    }

    fn onCtlReadable(self: *Daemon, cfd: posix.fd_t) void {
        defer posix.close(cfd); // close removes the knote
        var buf: [ctl.max_request]u8 = undefined;
        const n = posix.read(cfd, &buf) catch return;
        if (n == 0) return;

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.alloc);
        self.handleCtl(buf[0..n], &out);
        if (out.items.len > ctl.max_response) {
            out.shrinkRetainingCapacity(ctl.max_response);
            out.appendSlice(self.alloc, "\n... (truncated)\n") catch {};
        }
        var off: usize = 0;
        while (off < out.items.len) {
            const w = posix.write(cfd, out.items[off..]) catch return;
            if (w == 0) return;
            off += w;
        }
    }

    fn ctlPrint(self: *Daemon, out: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.allocPrint(self.alloc, fmt, args) catch return;
        defer self.alloc.free(s);
        out.appendSlice(self.alloc, s) catch {};
    }

    fn handleCtl(self: *Daemon, req: []const u8, out: *std.ArrayList(u8)) void {
        switch (ctl.parseCommand(req)) {
            .status => self.ctlStatus(out),
            .peers => self.ctlPeers(out),
            .backlog => self.ctlBacklog(out),
            .journal => self.ctlJournal(out),
            .resync => self.ctlResync(out),
            .conflicts_list => self.ctlConflictsList(out),
            .conflicts_restore => |name| self.ctlConflictsRestore(out, name),
            .conflicts_prune => |filter| self.ctlConflictsPrune(out, filter),
            .metrics => self.ctlMetrics(out),
            .massdelete => self.ctlMassdelete(out, false),
            .massdelete_resume => self.ctlMassdelete(out, true),
            .unknown => out.appendSlice(self.alloc, "ERR unknown command (status|peers|backlog|journal|resync|metrics|conflicts list|restore <name>|prune [substr]|massdelete [resume])\n") catch {},
        }
    }

    /// SIGHUP runtime reconfig (gap #19).  Reloadable without restart:
    /// the PSK (re-read from psk_file; applies to NEW handshakes — the
    /// established conns already authenticated), the peer list (NEW
    /// addresses get outbound dials; existing conns are untouched — a
    /// peer REMOVAL needs a restart), and rate_limit (stored for the
    /// Phase 3 enforcement).  Identity/topology fields (node_id,
    /// replicated_path, state_dir, listen, primary, tls_*) are NOT
    /// reloadable: a change logs a warning and keeps the running value.
    fn reloadConfig(self: *Daemon) void {
        const path = self.cfg_path orelse return;
        const fresh = config.load(path) orelse {
            log(.err, "SIGHUP: reload of {s} failed; keeping running config", .{path});
            return;
        };
        const cfg = self.cfg;
        if (!std.mem.eql(u8, fresh.node_id, cfg.node_id))
            log(.warn, "SIGHUP: node_id change ({s} -> {s}) requires restart; ignored", .{ cfg.node_id, fresh.node_id });
        if (!std.mem.eql(u8, fresh.replicated_path, cfg.replicated_path))
            log(.warn, "SIGHUP: replicated_path change ({s} -> {s}) requires restart; ignored", .{ cfg.replicated_path, fresh.replicated_path });
        if (!std.mem.eql(u8, fresh.state_dir, cfg.state_dir))
            log(.warn, "SIGHUP: state_dir change ({s} -> {s}) requires restart; ignored", .{ cfg.state_dir, fresh.state_dir });
        if (!std.mem.eql(u8, fresh.listen, cfg.listen))
            log(.warn, "SIGHUP: listen change ({s} -> {s}) requires restart; ignored", .{ cfg.listen, fresh.listen });
        if (fresh.primary != cfg.primary)
            log(.warn, "SIGHUP: primary change requires restart; ignored", .{});
        if (!std.mem.eql(u8, fresh.tls_cert, cfg.tls_cert) or
            !std.mem.eql(u8, fresh.tls_key, cfg.tls_key) or
            !std.mem.eql(u8, fresh.tls_ca, cfg.tls_ca) or
            fresh.tls_ktls != cfg.tls_ktls)
            log(.warn, "SIGHUP: tls_* changes require restart; ignored", .{});
        if (fresh.rate_limit != cfg.rate_limit)
            log(.info, "SIGHUP: rate_limit now {d} bytes/sec (enforcement is Phase 3)", .{fresh.rate_limit});

        // PSK re-read (even if psk_file path is unchanged — the CONTENT
        // may have been rotated).
        if (fresh.psk_file.len > 0) {
            if (std.fs.cwd().readFileAlloc(self.alloc, fresh.psk_file, 4096)) |buf| {
                defer self.alloc.free(buf);
                const trimmed = std.mem.trim(u8, buf, " \t\r\n");
                if (trimmed.len == 0) {
                    log(.err, "SIGHUP: psk_file {s} is empty; keeping current PSK", .{fresh.psk_file});
                } else if (std.mem.eql(u8, trimmed, self.psk)) {
                    log(.info, "SIGHUP: PSK unchanged", .{});
                } else if (self.alloc.dupe(u8, trimmed)) |owned| {
                    if (self.psk_owned) |old| self.alloc.free(old);
                    self.psk_owned = owned;
                    self.psk = owned;
                    log(.info, "SIGHUP: PSK reloaded (applies to new handshakes)", .{});
                } else |_| {
                    log(.err, "SIGHUP: PSK reload allocation failed; keeping current PSK", .{});
                }
            } else |err| {
                log(.err, "SIGHUP: cannot read psk_file {s}: {s}; keeping current PSK", .{ fresh.psk_file, @errorName(err) });
            }
        }

        // New peers get outbound dials; existing conns are untouched.
        var added: u64 = 0;
        for (fresh.peers[0..fresh.num_peers]) |peer_text| {
            const addr = server.parseHostPort(peer_text) catch {
                log(.warn, "SIGHUP: bad peer address {s}; skipped", .{peer_text});
                continue;
            };
            var nbuf: [64]u8 = undefined;
            const norm = std.fmt.bufPrint(&nbuf, "{f}", .{addr}) catch continue;
            var known = false;
            for (self.peers.items) |p| {
                const pa = p.addr orelse continue;
                var ebuf: [64]u8 = undefined;
                const es = std.fmt.bufPrint(&ebuf, "{f}", .{pa}) catch continue;
                if (std.mem.eql(u8, norm, es)) {
                    known = true;
                    break;
                }
            }
            if (known) continue;
            const p = self.alloc.create(Peer) catch break;
            p.* = Peer.init(self.alloc);
            p.outbound = true;
            p.addr = addr;
            p.next_retry_ms = 0; // dial on the next timer pass
            self.peers.append(self.alloc, p) catch {
                self.alloc.destroy(p);
                break;
            };
            added += 1;
            log(.info, "SIGHUP: new peer {s} (dialing)", .{norm});
        }
        log(.info, "SIGHUP: reload done ({d} new peers, {d} configured total)", .{ added, fresh.num_peers });
    }

    fn ctlStatus(self: *Daemon, out: *std.ArrayList(u8)) void {
        var live: u64 = 0;
        var tombs: u64 = 0;
        var it = self.cs.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.state == .live) live += 1 else tombs += 1;
        }
        var completing: u64 = 0;
        var iit = self.incoming.iterator();
        while (iit.next()) |e| {
            if (e.value_ptr.completing) completing += 1;
        }
        self.ctlPrint(out, "node_id: {s}\n", .{self.cfg.node_id});
        self.ctlPrint(out, "primary: {}\n", .{self.cfg.primary});
        self.ctlPrint(out, "resynced: {}\n", .{self.resynced});
        self.ctlPrint(out, "tree: {s}\n", .{self.cfg.replicated_path});
        self.ctlPrint(out, "state_dir: {s}\n", .{self.cfg.state_dir});
        self.ctlPrint(out, "records: {d} live, {d} tombstones\n", .{ live, tombs });
        self.ctlPrint(out, "local_next_seq: {d}\n", .{self.cs.local_next_seq});
        self.ctlPrint(out, "ring_seq: {d}\n", .{self.cs.ring_seq});
        self.ctlPrint(out, "state_at_open: {s}\n", .{if (self.cs.needs_scan) "empty/corrupt (rebuilt via scan floor)" else "loaded"});
        self.ctlPrint(out, "incoming: {d} fetches ({d} completing)\n", .{ self.incoming.count(), completing });
        self.ctlPrint(out, "mass-delete guard: {s} ({d} deletes in window)\n", .{
            if (self.guard.latched) "LATCHED — local tombstones suppressed" else "clear",
            self.guard.count,
        });
        self.ctlPrint(out, "fs: {s}\n", .{if (self.fs_frozen) "FROZEN (fsid mismatch — see log)" else "ok"});
    }

    /// Prometheus text exposition (gauges; brfsctl prepends the kernel
    /// counters).  brfs_member_vector_lag is the convergence health check:
    /// per member, the total seq distance between our content set and the
    /// member's last announced vector — 0 on every member means the mesh
    /// is caught up.
    fn ctlMetrics(self: *Daemon, out: *std.ArrayList(u8)) void {
        var live: u64 = 0;
        var tombs: u64 = 0;
        var it = self.cs.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.state == .live) live += 1 else tombs += 1;
        }
        var completing: u64 = 0;
        var iit = self.incoming.iterator();
        while (iit.next()) |e| {
            if (e.value_ptr.completing) completing += 1;
        }
        var peers_ready: u64 = 0;
        for (self.peers.items) |p| {
            if (p.state == .ready) peers_ready += 1;
        }
        self.comp.mutex.lock();
        const comp_jobs = self.comp.jobs.items.len;
        self.comp.mutex.unlock();

        self.ctlPrint(out, "# TYPE brfs_records gauge\n", .{});
        self.ctlPrint(out, "brfs_records{{node=\"{s}\",state=\"live\"}} {d}\n", .{ self.cfg.node_id, live });
        self.ctlPrint(out, "brfs_records{{node=\"{s}\",state=\"tombstone\"}} {d}\n", .{ self.cfg.node_id, tombs });
        self.ctlPrint(out, "# TYPE brfs_incoming_fetches gauge\n", .{});
        self.ctlPrint(out, "brfs_incoming_fetches{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, self.incoming.count() });
        self.ctlPrint(out, "brfs_incoming_completing{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, completing });
        self.ctlPrint(out, "# TYPE brfs_journal_pending gauge\n", .{});
        self.ctlPrint(out, "brfs_journal_pending{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, self.jr.pendingCount() });
        self.ctlPrint(out, "# TYPE brfs_completion_queue gauge\n", .{});
        self.ctlPrint(out, "brfs_completion_queue{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, comp_jobs });
        self.ctlPrint(out, "# TYPE brfs_peers gauge\n", .{});
        self.ctlPrint(out, "brfs_peers{{node=\"{s}\",state=\"ready\"}} {d}\n", .{ self.cfg.node_id, peers_ready });
        self.ctlPrint(out, "brfs_peers{{node=\"{s}\",state=\"total\"}} {d}\n", .{ self.cfg.node_id, self.peers.items.len });
        self.ctlPrint(out, "# TYPE brfs_massdelete_latched gauge\n", .{});
        self.ctlPrint(out, "brfs_massdelete_latched{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, @intFromBool(self.guard.latched) });
        self.ctlPrint(out, "# TYPE brfs_fs_frozen gauge\n", .{});
        self.ctlPrint(out, "brfs_fs_frozen{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, @intFromBool(self.fs_frozen) });
        self.ctlPrint(out, "# TYPE brfs_resynced gauge\n", .{});
        self.ctlPrint(out, "brfs_resynced{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, @intFromBool(self.resynced) });
        self.ctlPrint(out, "# TYPE brfs_ring_seq gauge\n", .{});
        self.ctlPrint(out, "brfs_ring_seq{{node=\"{s}\"}} {d}\n", .{ self.cfg.node_id, self.cs.ring_seq });

        const ours = resync.buildVector(&self.cs);
        self.ctlPrint(out, "# TYPE brfs_member_vector_lag gauge\n", .{});
        for (&self.member_vectors) |*mv| {
            if (!mv.used) continue;
            var lag: u64 = 0;
            for (ours.vector[0..ours.count]) |ve| {
                lag += ve.max_seq -| mv.maxSeq(ve.origin);
            }
            self.ctlPrint(out, "brfs_member_vector_lag{{node=\"{s}\",member=\"{x}\"}} {d}\n", .{ self.cfg.node_id, mv.node_hash, lag });
        }
    }

    fn ctlMassdelete(self: *Daemon, out: *std.ArrayList(u8), do_resume: bool) void {
        if (!do_resume) {
            self.ctlPrint(out, "mass-delete guard: {s}\n", .{if (self.guard.latched) "LATCHED (local tombstones suppressed)" else "clear"});
            self.ctlPrint(out, "window: {d} deletes / {d}ms (trips at >= {d} deletes AND > 50% of the live tree)\n", .{
                self.guard.count, guard_mod.window_ms, guard_mod.floor,
            });
            return;
        }
        const was = self.guard.latched;
        self.guard.release(peer_mod.nowMs());
        // The rescan floor re-derives the suppressed deletes as honest
        // tombstones: an intentional rm -rf still converges, one
        // confirmation later.
        self.need_rescan = true;
        self.ctlPrint(out, "mass-delete guard released ({s}); rescan scheduled\n", .{if (was) "was latched" else "was not latched"});
    }

    fn ctlPeers(self: *Daemon, out: *std.ArrayList(u8)) void {
        for (self.peers.items) |p| {
            var abuf: [64]u8 = undefined;
            const addr_s = if (p.addr) |a| std.fmt.bufPrint(&abuf, "{f}", .{a}) catch "?" else "-";
            self.ctlPrint(out, "{s}\t{s}\t{s}\t{s}\twbuf={d}\n", .{
                p.node_id orelse "?",
                @tagName(p.state),
                if (p.outbound) "outbound" else "inbound",
                addr_s,
                p.wbuf.items.len,
            });
        }
    }

    fn ctlBacklog(self: *Daemon, out: *std.ArrayList(u8)) void {
        self.comp.mutex.lock();
        const comp_jobs = self.comp.jobs.items.len;
        self.comp.mutex.unlock();
        self.ctlPrint(out, "journal pending: {d}\n", .{self.jr.pendingCount()});
        self.ctlPrint(out, "incoming fetches: {d}\n", .{self.incoming.count()});
        self.ctlPrint(out, "completion queue: {d}\n", .{comp_jobs});
    }

    fn ctlJournal(self: *Daemon, out: *std.ArrayList(u8)) void {
        self.ctlPrint(out, "pending: {d}\n", .{self.jr.pendingCount()});
        self.ctlPrint(out, "moves in flight: {d}\n", .{self.jr.moves.count()});
        self.ctlPrint(out, "echo markers: {d}\n", .{self.jr.echoes.count()});
        self.ctlPrint(out, "high_seq: {d}\n", .{self.jr.high_seq});
    }

    fn ctlResync(self: *Daemon, out: *std.ArrayList(u8)) void {
        var n: u64 = 0;
        for (self.peers.items) |p| {
            if (p.state == .ready) {
                self.sendResyncReq(p);
                n += 1;
            }
        }
        self.need_rescan = true; // local floor too
        self.ctlPrint(out, "resync requested: {d} peers, local rescan scheduled\n", .{n});
    }

    fn ctlConflictsList(self: *Daemon, out: *std.ArrayList(u8)) void {
        var dir = std.fs.cwd().openDir(self.inst.conflicts, .{ .iterate = true }) catch {
            out.appendSlice(self.alloc, "ERR cannot open conflicts dir\n") catch {};
            return;
        };
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch null) |ent| {
            const st = dir.statFile(ent.name) catch null;
            self.ctlPrint(out, "{s}\t{s}\t{d}\n", .{
                ent.name,
                @tagName(ent.kind),
                if (st) |s| s.size else 0,
            });
        }
    }

    fn ctlConflictsRestore(self: *Daemon, out: *std.ArrayList(u8), name: []const u8) void {
        // Quarantined names are "{path}.{ms-stamp}": restore strips the
        // stamp.  No echo marker: the rename INTO the tree is announced as
        // fresh local content (the operator's intent).
        if (!contentset.validRelPath(name)) {
            out.appendSlice(self.alloc, "ERR bad conflicts name\n") catch {};
            return;
        }
        const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse {
            out.appendSlice(self.alloc, "ERR name has no timestamp suffix\n") catch {};
            return;
        };
        const suffix = name[dot + 1 ..];
        if (suffix.len == 0) {
            out.appendSlice(self.alloc, "ERR name has no timestamp suffix\n") catch {};
            return;
        }
        for (suffix) |ch| {
            if (!std.ascii.isDigit(ch)) {
                out.appendSlice(self.alloc, "ERR name has no timestamp suffix\n") catch {};
                return;
            }
        }
        const target = name[0..dot];
        if (!contentset.validRelPath(target)) {
            out.appendSlice(self.alloc, "ERR bad restore target\n") catch {};
            return;
        }
        const src = std.fs.path.join(self.alloc, &.{ self.inst.conflicts, name }) catch return;
        defer self.alloc.free(src);
        const dst = std.fs.path.join(self.alloc, &.{ self.inst.root, target }) catch return;
        defer self.alloc.free(dst);
        if (std.fs.path.dirname(dst)) |dir| {
            const abs = std.fs.path.join(self.alloc, &.{ self.inst.root, dir }) catch return;
            defer self.alloc.free(abs);
            std.fs.cwd().makePath(abs) catch {};
        }
        posix.rename(src, dst) catch |err| {
            self.ctlPrint(out, "ERR restore failed: {s}\n", .{@errorName(err)});
            return;
        };
        self.ctlPrint(out, "restored {s} -> {s}\n", .{ name, target });
    }

    fn ctlConflictsPrune(self: *Daemon, out: *std.ArrayList(u8), filter: ?[]const u8) void {
        var dir = std.fs.cwd().openDir(self.inst.conflicts, .{ .iterate = true }) catch {
            out.appendSlice(self.alloc, "ERR cannot open conflicts dir\n") catch {};
            return;
        };
        defer dir.close();
        var pruned: u64 = 0;
        var it = dir.iterate();
        while (it.next() catch null) |ent| {
            if (filter) |f| {
                if (std.mem.indexOf(u8, ent.name, f) == null) continue;
            }
            if (ent.kind == .directory)
                dir.deleteTree(ent.name) catch continue
            else
                dir.deleteFile(ent.name) catch continue;
            pruned += 1;
        }
        self.ctlPrint(out, "pruned {d}\n", .{pruned});
    }
};

fn peerName(p: *Peer) []const u8 {
    return p.node_id orelse "?";
}

// ---- tests ----

test "incoming tried-list dedups and bounds source fallbacks" {
    const t = std.testing;
    var inc = Incoming{
        .ver = .{},
        .size = 0,
        .sha256 = [_]u8{0} ** 32,
        .mode = 0,
        .mtime_sec = 0,
        .mtime_nsec = 0,
        .deadline_ms = 0,
    };
    try t.expect(!inc.wasTried("node-a"));
    inc.markTried("node-a");
    try t.expect(inc.wasTried("node-a"));
    try t.expect(!inc.wasTried("node-b"));
    inc.markTried("node-a"); // no duplicate growth
    try t.expectEqual(@as(u8, 1), inc.tried_n);
    // Bounded: never grows past max_peers.
    var i: usize = 0;
    while (i < config.max_peers + 4) : (i += 1) {
        var buf: [24]u8 = undefined;
        const nid = std.fmt.bufPrint(&buf, "n{d}", .{i}) catch unreachable;
        inc.markTried(nid);
    }
    try t.expectEqual(@as(u8, config.max_peers), inc.tried_n);
}
