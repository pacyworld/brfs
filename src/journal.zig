//! journal.zig — the pending-change queue.
//!
//! Kernel events (already resolved to paths by the caller via the content
//! set's dir index) are coalesced per path and debounced: a file is only
//! processed after a quiet period with no further events (protocol.md
//! "Write stability" — the ring emits no CLOSE_WRITE, so quiescence IS the
//! signal).  Per-path monotonic ordering: every event carries the ring seq;
//! replays after a restart re-enter harmlessly because processing is
//! idempotent and content-set versions gate announcements.
//!
//! Rename pairing: MOVE_FROM/MOVE_TO share the kernel rename cookie
//! (cookie 0 is a valid first cookie — pair by cookie, not by "nonzero").
//! An unpaired MOVE_FROM at expiry is a move-out-of-tree (delete); an
//! unpaired MOVE_TO is a move-in (content upsert).
//!
//! Self-echo suppression (rule 6, T7): the installer registers an echo
//! marker (path + installed sha256) before its rename-into-place; the
//! resulting events are swallowed ONLY after the caller verifies the file
//! content still matches the installed version — a genuine local edit
//! racing an install must not be eaten.
//!
//! Pure bookkeeping: no filesystem or socket IO in here.

const std = @import("std");
const Allocator = std.mem.Allocator;
const events = @import("events.zig");

pub const ResolvedEvent = struct {
    path: []const u8,
    op: events.Op, // create/modify/delete/move_from/move_to/attrib
    cookie: u32 = 0,
    is_dir: bool = false,
    seq: u64,
};

pub const Work = union(enum) {
    upsert: Entry, // content or metadata changed (or moved-in)
    delete: Entry, // removed (or moved out of tree)
    rename: Rename,
};

pub const Entry = struct {
    path: []u8, // owned
    is_dir: bool,
    last_seq: u64,
};

pub const Rename = struct {
    from: []u8, // owned
    to: []u8, // owned
    is_dir: bool,
    last_seq: u64,
    dirty: bool = false, // content changed at the destination after the rename
};

/// What the installer expects its own activity to look like.
/// install: next content event for the path must match (sha256, size) to
/// be swallowed — or, when fileid != 0 (async completion worker), the
/// event's subject (fileid, gen) must BE the staged file: an O(1) compare
/// that never re-hashes a big file on the core loop.  fileid-marked
/// install echoes are NOT consumed by swallowing: an install emits two
/// events (MOVE_TO + ATTRIB) and both must swallow — the daemon's
/// completion callback clears the marker.  move_from: the path must be
/// ABSENT (our own rename's FROM half) to be swallowed.  Mismatch on
/// either = genuine local change.
pub const Echo = struct {
    kind: EchoKind,
    sha256: [32]u8,
    size: u64,
    fileid: u64 = 0,
    gen: u64 = 0,

    pub const EchoKind = enum { install, move_from };
};

const Pending = struct {
    path: []u8, // owned; the map key (rename entries: the ORIGINAL path)
    kind: Kind,
    is_dir: bool,
    deadline_ms: i64,
    last_seq: u64,
    cookie: u32 = 0, // pending move_from: pairing key
    move_to: ?[]u8 = null, // paired rename destination (owned); also the map key
    dirty: bool = false, // rename + subsequent content change at the destination
};

const Kind = enum { upsert, delete, move_from, rename };

pub const Journal = struct {
    alloc: Allocator,
    debounce_ms: i64,
    entries: std.StringHashMap(*Pending),
    moves: std.AutoHashMap(u32, *Pending), // cookie -> pending move_from
    echoes: std.StringHashMap(Echo),
    high_seq: u64 = 0,

    pub fn init(alloc: Allocator, debounce_ms: i64) Journal {
        return .{
            .alloc = alloc,
            .debounce_ms = debounce_ms,
            .entries = std.StringHashMap(*Pending).init(alloc),
            .moves = std.AutoHashMap(u32, *Pending).init(alloc),
            .echoes = std.StringHashMap(Echo).init(alloc),
        };
    }

    pub fn deinit(self: *Journal) void {
        var it = self.entries.iterator();
        while (it.next()) |e|
            self.freePending(e.value_ptr.*);
        self.entries.deinit();
        self.moves.deinit();
        var eit = self.echoes.iterator();
        while (eit.next()) |e|
            self.alloc.free(e.key_ptr.*);
        self.echoes.deinit();
    }

    fn freePending(self: *Journal, p: *Pending) void {
        self.alloc.free(p.path);
        if (p.move_to) |m| self.alloc.free(m);
        self.alloc.destroy(p);
    }

    pub fn pendingCount(self: *const Journal) usize {
        return self.entries.count();
    }

    /// Feed one resolved kernel event.
    pub fn add(self: *Journal, ev: ResolvedEvent, now_ms: i64) !void {
        if (ev.seq > self.high_seq) self.high_seq = ev.seq;
        switch (ev.op) {
            .create, .modify, .attrib => try self.coalesceContent(ev, now_ms),
            .delete => try self.coalesceDelete(ev, now_ms),
            .move_from => try self.addMoveFrom(ev, now_ms),
            .move_to => try self.addMoveTo(ev, now_ms),
            .overflow => {}, // handled by the caller (scan trigger)
            _ => {},
        }
    }

    fn coalesceContent(self: *Journal, ev: ResolvedEvent, now_ms: i64) !void {
        if (self.entries.getPtr(ev.path)) |pp| {
            const p = pp.*;
            if (p.kind == .rename) {
                // Content changed at the rename destination: keep the
                // rename (no delete+create artifacts, T10) and flag the
                // content dirty so the processor re-announces after it.
                p.dirty = true;
            } else {
                // Content change after a pending delete = recreated.
                p.kind = .upsert;
                p.is_dir = p.is_dir or ev.is_dir;
            }
            p.deadline_ms = now_ms + self.debounce_ms;
            p.last_seq = @max(p.last_seq, ev.seq);
            return;
        }
        _ = try self.newEntry(ev.path, .upsert, ev.is_dir, now_ms, ev.seq);
    }

    fn coalesceDelete(self: *Journal, ev: ResolvedEvent, now_ms: i64) !void {
        if (self.entries.getPtr(ev.path)) |pp| {
            const p = pp.*;
            // Rename entries are keyed by destination, so a delete of the
            // renamed file lands here: net effect is a delete of the
            // destination (and the source never leaves the content set
            // on the wire — it was never announced).
            if (p.kind == .move_from) _ = self.moves.remove(p.cookie);
            if (p.kind == .rename) {
                self.alloc.free(p.path);
                p.path = p.move_to.?;
                p.move_to = null;
            }
            p.kind = .delete;
            p.deadline_ms = now_ms + self.debounce_ms;
            p.last_seq = @max(p.last_seq, ev.seq);
            return;
        }
        _ = try self.newEntry(ev.path, .delete, ev.is_dir, now_ms, ev.seq);
    }

    fn addMoveFrom(self: *Journal, ev: ResolvedEvent, now_ms: i64) !void {
        // A pending entry for the same path is superseded (its content is
        // leaving); the rename (or the eventual delete) covers it.  A
        // rename entry keyed by this path (a previous rename TO here)
        // chains: a->b then b->c stays pending as a->c.
        if (self.entries.fetchRemove(ev.path)) |old| {
            const p = old.value;
            if (p.kind == .move_from) _ = self.moves.remove(p.cookie);
            if (p.kind == .rename) {
                self.alloc.free(p.move_to.?);
                p.move_to = null;
                p.kind = .move_from;
                p.cookie = ev.cookie;
                p.deadline_ms = now_ms + self.debounce_ms;
                p.last_seq = @max(p.last_seq, ev.seq);
                try self.entries.put(p.path, p);
                try self.moves.put(ev.cookie, p);
                return;
            }
            self.freePending(p);
        }
        const p = try self.newEntry(ev.path, .move_from, ev.is_dir, now_ms, ev.seq);
        p.cookie = ev.cookie;
        try self.moves.put(ev.cookie, p);
    }

    fn addMoveTo(self: *Journal, ev: ResolvedEvent, now_ms: i64) !void {
        if (self.moves.fetchRemove(ev.cookie)) |kv| {
            const p = kv.value;
            // Paired.  Re-key by the destination so later events for the
            // new name (delete, content) coalesce onto this entry.  A
            // stale pending entry at the destination is replaced by the
            // rename (same path src==dst is a no-op rename: p is its own
            // destination entry).
            _ = self.entries.remove(p.path);
            if (self.entries.fetchRemove(ev.path)) |old| {
                if (old.value != p) {
                    if (old.value.kind == .move_from) _ = self.moves.remove(old.value.cookie);
                    self.freePending(old.value);
                }
            }
            p.kind = .rename;
            p.move_to = try self.alloc.dupe(u8, ev.path);
            p.deadline_ms = now_ms + self.debounce_ms;
            p.last_seq = @max(p.last_seq, ev.seq);
            try self.entries.put(p.move_to.?, p);
            return;
        }
        // No pending source: moved in from outside the tree (or the FROM
        // half predates our startup). Treat as a content change.
        try self.coalesceContent(ev, now_ms);
    }

    fn newEntry(self: *Journal, path: []const u8, kind: Kind, is_dir: bool, now_ms: i64, seq: u64) !*Pending {
        const owned = try self.alloc.dupe(u8, path);
        errdefer self.alloc.free(owned);
        const p = try self.alloc.create(Pending);
        p.* = .{
            .path = owned,
            .kind = kind,
            .is_dir = is_dir,
            .deadline_ms = now_ms + self.debounce_ms,
            .last_seq = seq,
        };
        try self.entries.put(owned, p);
        return p;
    }

    /// Move every expired entry into `out` as work items.  Ownership of the
    /// path allocations transfers to the caller (see freeWork).
    pub fn collectReady(self: *Journal, now_ms: i64, out: *std.ArrayList(Work)) !void {
        var ready: std.ArrayList([]const u8) = .empty;
        defer ready.deinit(self.alloc);
        var it = self.entries.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.*.deadline_ms <= now_ms)
                try ready.append(self.alloc, e.key_ptr.*);
        }
        for (ready.items) |key| {
            const kv = self.entries.fetchRemove(key).?;
            const p = kv.value;
            switch (p.kind) {
                .upsert => try out.append(self.alloc, .{ .upsert = .{
                    .path = p.path,
                    .is_dir = p.is_dir,
                    .last_seq = p.last_seq,
                } }),
                .delete => try out.append(self.alloc, .{ .delete = .{
                    .path = p.path,
                    .is_dir = p.is_dir,
                    .last_seq = p.last_seq,
                } }),
                .rename => try out.append(self.alloc, .{ .rename = .{
                    .from = p.path,
                    .to = p.move_to.?,
                    .is_dir = p.is_dir,
                    .last_seq = p.last_seq,
                    .dirty = p.dirty,
                } }),
                .move_from => {
                    // Never paired: the file left the tree.
                    _ = self.moves.remove(p.cookie);
                    try out.append(self.alloc, .{ .delete = .{
                        .path = p.path,
                        .is_dir = p.is_dir,
                        .last_seq = p.last_seq,
                    } });
                },
            }
            // Path ownership moved into the work item; free only the rest.
            if (p.kind != .rename)
                if (p.move_to) |m| self.alloc.free(m);
            self.alloc.destroy(p);
        }
    }

    pub fn freeWork(self: *Journal, work: *Work) void {
        switch (work.*) {
            .upsert => |*e| self.alloc.free(e.path),
            .delete => |*e| self.alloc.free(e.path),
            .rename => |*r| {
                self.alloc.free(r.from);
                self.alloc.free(r.to);
            },
        }
    }

    /// Register an install echo: the next content event for path that still
    /// matches (sha256, size) is our own rename-into-place, not a change.
    pub fn noteEcho(self: *Journal, path: []const u8, kind: Echo.EchoKind, sha256: [32]u8, size: u64) !void {
        const gop = try self.echoes.getOrPut(path);
        if (!gop.found_existing)
            gop.key_ptr.* = try self.alloc.dupe(u8, path);
        gop.value_ptr.* = .{ .kind = kind, .sha256 = sha256, .size = size };
    }

    /// Install echo carrying the staged file's identity: the swallow is an
    /// O(1) (fileid, gen) compare against the kernel event's subject, and
    /// the marker persists (both the MOVE_TO and the ATTRIB of one install
    /// must swallow) until the daemon's completion callback clears it.
    pub fn noteEchoFile(self: *Journal, path: []const u8, sha256: [32]u8, size: u64, fileid: u64, gen: u64) !void {
        const gop = try self.echoes.getOrPut(path);
        if (!gop.found_existing)
            gop.key_ptr.* = try self.alloc.dupe(u8, path);
        gop.value_ptr.* = .{ .kind = .install, .sha256 = sha256, .size = size, .fileid = fileid, .gen = gen };
    }

    /// Inspect (without consuming) a pending echo marker.
    pub fn peekEcho(self: *Journal, path: []const u8) ?Echo {
        return self.echoes.get(path);
    }

    /// Consume the echo marker after the caller verified the content.
    pub fn clearEcho(self: *Journal, path: []const u8) void {
        if (self.echoes.fetchRemove(path)) |kv|
            self.alloc.free(kv.key);
    }

    /// Milliseconds until the next entry expires; null when idle.  The
    /// caller folds this into its kevent timeout.
    pub fn nextDeadlineIn(self: *const Journal, now_ms: i64) ?i64 {
        var best: ?i64 = null;
        var it = self.entries.iterator();
        while (it.next()) |e| {
            const d = e.value_ptr.*.deadline_ms - now_ms;
            if (best == null or d < best.?) best = d;
        }
        return best;
    }
};

// ---- tests ----

const t = std.testing;

fn mkEv(path: []const u8, op: events.Op, seq: u64) ResolvedEvent {
    return .{ .path = path, .op = op, .seq = seq };
}

fn mkEvC(path: []const u8, op: events.Op, cookie: u32, seq: u64) ResolvedEvent {
    return .{ .path = path, .op = op, .cookie = cookie, .seq = seq };
}

fn drain(j: *Journal, now: i64) []Work {
    var out: std.ArrayList(Work) = .empty;
    j.collectReady(now, &out) catch unreachable;
    return out.toOwnedSlice(t.allocator) catch unreachable;
}

fn freeAll(j: *Journal, works: []Work) void {
    for (works) |*w| j.freeWork(w);
    t.allocator.free(works);
}

test "coalesce: N rapid writes become one upsert" {
    var j = Journal.init(t.allocator, 200);
    defer j.deinit();
    const now: i64 = 1_000_000;
    var seq: u64 = 1;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try j.add(mkEv("f.txt", .modify, seq), now + @as(i64, @intCast(i)));
        seq += 1;
    }
    try t.expectEqual(@as(usize, 1), j.pendingCount());

    // Last event at now+49, deadline now+249: not yet expired just before.
    const early = drain(&j, now + 248);
    defer freeAll(&j, early);
    try t.expectEqual(@as(usize, 0), early.len);
    const works = drain(&j, now + 249);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expectEqualStrings("f.txt", works[0].upsert.path);
    try t.expectEqual(@as(u64, 50), works[0].upsert.last_seq);
}

test "modify then delete coalesces to delete" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEv("f.txt", .modify, 1), 0);
    try j.add(mkEv("f.txt", .delete, 2), 10);
    const works = drain(&j, 200);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expect(works[0] == .delete);
}

test "delete then create coalesces back to upsert" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEv("f.txt", .delete, 1), 0);
    try j.add(mkEv("f.txt", .create, 2), 10);
    const works = drain(&j, 200);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expect(works[0] == .upsert);
}

test "rename pairs by cookie (cookie 0 is valid)" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEvC("old.txt", .move_from, 0, 1), 0); // first post-boot cookie
    try j.add(mkEvC("new.txt", .move_to, 0, 2), 5);
    const works = drain(&j, 200);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expectEqualStrings("old.txt", works[0].rename.from);
    try t.expectEqualStrings("new.txt", works[0].rename.to);
}

test "unpaired move_from expires as delete; unpaired move_to as upsert" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEvC("gone.txt", .move_from, 7, 1), 0);
    try j.add(mkEvC("arrived.txt", .move_to, 9, 2), 0);
    const works = drain(&j, 200);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 2), works.len);
    var saw_del = false;
    var saw_up = false;
    for (works) |w| switch (w) {
        .delete => |e| {
            saw_del = true;
            try t.expectEqualStrings("gone.txt", e.path);
        },
        .upsert => |e| {
            saw_up = true;
            try t.expectEqualStrings("arrived.txt", e.path);
        },
        .rename => return error.UnexpectedRename,
    };
    try t.expect(saw_del and saw_up);
}

test "rename then delete nets a delete of the destination" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEvC("a.txt", .move_from, 3, 1), 0);
    try j.add(mkEvC("b.txt", .move_to, 3, 2), 5);
    try j.add(mkEv("b.txt", .delete, 3), 10);
    const works = drain(&j, 300);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expect(works[0] == .delete);
    try t.expectEqualStrings("b.txt", works[0].delete.path);
}

test "rename then modify keeps rename and marks dirty" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEvC("a.txt", .move_from, 4, 1), 0);
    try j.add(mkEvC("b.txt", .move_to, 4, 2), 5);
    try j.add(mkEv("b.txt", .modify, 3), 10);
    const works = drain(&j, 300);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expect(works[0] == .rename);
    try t.expectEqualStrings("a.txt", works[0].rename.from);
    try t.expectEqualStrings("b.txt", works[0].rename.to);
    try t.expect(works[0].rename.dirty);
}

test "rename chain a->b->c nets a single rename a->c" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEvC("a.txt", .move_from, 1, 1), 0);
    try j.add(mkEvC("b.txt", .move_to, 1, 2), 5);
    try j.add(mkEvC("b.txt", .move_from, 2, 3), 10);
    try j.add(mkEvC("c.txt", .move_to, 2, 4), 15);
    try t.expectEqual(@as(usize, 1), j.pendingCount());
    const works = drain(&j, 300);
    defer freeAll(&j, works);
    try t.expectEqual(@as(usize, 1), works.len);
    try t.expectEqualStrings("a.txt", works[0].rename.from);
    try t.expectEqualStrings("c.txt", works[0].rename.to);
}

test "echo marker lifecycle" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("x", &sha, .{});
    try j.noteEcho("f.txt", .install, sha, 1);
    try t.expect(j.peekEcho("f.txt") != null);
    j.clearEcho("f.txt");
    try t.expect(j.peekEcho("f.txt") == null);
}

test "identity echo marker carries the staged fileid/gen" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    const sha = [_]u8{7} ** 32;
    try j.noteEchoFile("big.bin", sha, 200 << 20, 4242, 77);
    const e = j.peekEcho("big.bin").?;
    try t.expectEqual(Echo.EchoKind.install, e.kind);
    try t.expectEqual(@as(u64, 4242), e.fileid);
    try t.expectEqual(@as(u64, 77), e.gen);
    // Plain noteEcho stays identity-less (sha/size fallback path).
    try j.noteEcho("old.txt", .install, sha, 1);
    try t.expectEqual(@as(u64, 0), j.peekEcho("old.txt").?.fileid);
    j.clearEcho("big.bin");
    try t.expect(j.peekEcho("big.bin") == null);
}

test "high_seq tracks the maximum seen" {
    var j = Journal.init(t.allocator, 100);
    defer j.deinit();
    try j.add(mkEv("a", .modify, 5), 0);
    try j.add(mkEv("b", .modify, 3), 0); // replayed older seq
    try j.add(mkEv("c", .modify, 9), 0);
    try t.expectEqual(@as(u64, 9), j.high_seq);
}
