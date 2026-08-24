//! resync.zig — the catch-up layers that make the ring an accelerator,
//! never a dependency.
//!
//! Two mechanisms:
//!
//! 1. Startup scan (layer 3): walk the replicated tree, compare
//!    (size, mtime) against the persisted content set, hash only
//!    suspicious entries, and synthesize journal entries for everything
//!    that changed while we were down (creations, modifications, deletes —
//!    including resurrection over a tombstone: the file exists, so it
//!    lives, with a fresh local version).  Also rebuilds the content set's
//!    dir index so kernel events resolve to paths again.
//!
//! 2. RESYNC pull (layer 4): a version vector (per-origin max seq)
//!    exchanged with peers; the sender streams RESYNC_ENTRY for every
//!    record the receiver's vector doesn't cover.  Drives both the
//!    initial-seed join (gap #8: non-primary with an empty set pulls
//!    BEFORE announcing anything local) and offline-node catch-up (T6).

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const contentset = @import("contentset.zig");
const protocol = @import("protocol.zig");
const journal = @import("journal.zig");
const installer = @import("installer.zig");

pub const ScanStats = struct {
    seen: u64 = 0,
    announced_new: u64 = 0,
    announced_modified: u64 = 0,
    announced_deleted: u64 = 0,
    unchanged: u64 = 0,
};

fn recordFromStat(st: posix.Stat, is_dir: bool, ver: contentset.Version, sha: [32]u8) contentset.Record {
    return .{
        .id = .{
            .fsid = @intCast(st.dev),
            .fileid = @intCast(st.ino),
            .gen = @intCast(st.gen),
        },
        .ver = ver,
        .size = @intCast(@max(st.size, 0)),
        .mtime_sec = @intCast(st.mtim.sec),
        .mtime_nsec = @intCast(@max(st.mtim.nsec, 0)),
        .mode = @intCast(@as(u32, @intCast(st.mode)) & 0o7777),
        .is_dir = is_dir,
        .state = .live,
        .sha256 = sha,
    };
}

/// Walk the tree, reconcile against the content set, synthesize journal
/// entries (debounced/coalesced with any live ring events) for deltas.
/// Local mutations found by the scan get fresh local versions.
pub fn scan(
    alloc: Allocator,
    root: []const u8,
    cs: *contentset.ContentSet,
    j: *journal.Journal,
    now_ms: i64,
) !ScanStats {
    var stats = ScanStats{};
    var seen = std.StringHashMap(void).init(alloc);
    defer {
        var it = seen.iterator();
        while (it.next()) |e| alloc.free(e.key_ptr.*);
        seen.deinit();
    }

    var root_dir = try std.fs.cwd().openDir(root, .{ .iterate = true });
    defer root_dir.close();
    var walker = try root_dir.walk(alloc);
    defer walker.deinit();

    while (try walker.next()) |ent| {
        // The walker yields paths relative to root with native separators.
        const rel = try alloc.dupe(u8, ent.path);
        defer alloc.free(rel);
        try seen.put(try alloc.dupe(u8, rel), {});
        stats.seen += 1;

        const abs = try std.fs.path.join(alloc, &.{ root, rel });
        defer alloc.free(abs);
        const st = installer.statPath(abs) catch continue; // raced a delete
        const is_dir = installer.isDir(st);

        if (cs.lookup(rel)) |rec| {
            if (rec.state == .live) {
                if (is_dir) {
                    // Refresh identity (inode reuse across restarts); no
                    // announce for dirs that still exist.
                    var r = rec.*;
                    r.id = recordFromStat(st, true, rec.ver, rec.sha256).id;
                    try cs.upsert(rel, r);
                    stats.unchanged += 1;
                    continue;
                }
                if (rec.size == st.size and rec.mtime_sec == st.mtim.sec and
                    rec.mtime_nsec == @as(u32, @intCast(@max(st.mtim.nsec, 0))))
                {
                    var r = rec.*;
                    r.id = recordFromStat(st, false, rec.ver, rec.sha256).id;
                    try cs.upsert(rel, r);
                    stats.unchanged += 1;
                    continue;
                }
                // Suspicious: hash to decide.
                const sha = installer.hashFile(abs) catch continue;
                if (std.mem.eql(u8, &sha, &rec.sha256)) {
                    var r = rec.*;
                    r.size = @intCast(@max(st.size, 0));
                    r.mtime_sec = @intCast(st.mtim.sec);
                    r.mtime_nsec = @intCast(@max(st.mtim.nsec, 0));
                    r.id = recordFromStat(st, false, rec.ver, sha).id;
                    try cs.upsert(rel, r);
                    stats.unchanged += 1;
                    continue;
                }
                // Modified while we were down.
                const ver = cs.nextVersion();
                try cs.upsert(rel, recordFromStat(st, false, ver, sha));
                try j.add(.{ .path = rel, .op = .modify, .is_dir = false, .seq = cs.ring_seq }, now_ms);
                stats.announced_modified += 1;
            } else {
                // Tombstone but the file exists: it was recreated while we
                // were down.  Resurrect with a fresh local version (gap #9
                // direction; the rule locks with LMDB in Phase 2).
                const sha = if (is_dir) [_]u8{0} ** 32 else installer.hashFile(abs) catch continue;
                const ver = cs.nextVersion();
                try cs.upsert(rel, recordFromStat(st, is_dir, ver, sha));
                try j.add(.{ .path = rel, .op = .create, .is_dir = is_dir, .seq = cs.ring_seq }, now_ms);
                stats.announced_new += 1;
            }
        } else {
            // Never seen: local creation while we were down (or first-ever
            // scan of a primary's seeded tree).
            const sha = if (is_dir) [_]u8{0} ** 32 else installer.hashFile(abs) catch continue;
            const ver = cs.nextVersion();
            try cs.upsert(rel, recordFromStat(st, is_dir, ver, sha));
            try j.add(.{ .path = rel, .op = .create, .is_dir = is_dir, .seq = cs.ring_seq }, now_ms);
            stats.announced_new += 1;
        }
    }

    // Anything live in the set but absent on disk was deleted while down.
    var gone: std.ArrayList([]const u8) = .empty;
    defer gone.deinit(alloc);
    var it = cs.map.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.state == .live and !seen.contains(e.key_ptr.*))
            try gone.append(alloc, e.key_ptr.*);
    }
    for (gone.items) |path| {
        const rec = cs.lookup(path).?;
        var r = rec.*;
        r.state = .deleted;
        r.ver = cs.nextVersion();
        try cs.upsert(path, r);
        try j.add(.{ .path = path, .op = .delete, .is_dir = rec.is_dir, .seq = cs.ring_seq }, now_ms);
        stats.announced_deleted += 1;
    }

    return stats;
}

/// Our version vector: per-origin max seq over all records (tombstones
/// included — they must propagate too).
pub fn buildVector(cs: *const contentset.ContentSet) protocol.ResyncReq {
    var req = protocol.ResyncReq{ .vector = undefined, .count = 0 };
    var it = cs.map.iterator();
    while (it.next()) |e| {
        const v = e.value_ptr.ver;
        var found = false;
        for (req.vector[0..req.count]) |*ve| {
            if (ve.origin == v.origin) {
                ve.max_seq = @max(ve.max_seq, v.seq);
                found = true;
                break;
            }
        }
        if (!found and req.count < protocol.max_vector) {
            req.vector[req.count] = .{ .origin = v.origin, .max_seq = v.seq };
            req.count += 1;
        }
    }
    return req;
}

/// Sender-side filter: does the receiver's vector need this record?
pub fn vectorCovers(req: *const protocol.ResyncReq, ver: contentset.Version) bool {
    for (req.vector[0..req.count]) |ve| {
        if (ve.origin == ver.origin) return ver.seq <= ve.max_seq;
    }
    return false;
}

/// Receiver-side decision for one RESYNC_ENTRY.
pub const EntryAction = enum { ignore, fetch, adopt, tombstone };

pub fn entryAction(cs: *const contentset.ContentSet, entry: protocol.ResyncEntry) EntryAction {
    if (entry.state == .deleted) {
        // Adopt tombstones we don't already cover (idempotent).
        if (cs.lookup(entry.path)) |rec| {
            return switch (contentset.relate(entry.ver, rec.ver)) {
                .same, .older, .conflict_stored_wins => .ignore,
                else => .tombstone,
            };
        }
        return .tombstone;
    }
    if (cs.lookup(entry.path)) |rec| {
        switch (contentset.relate(entry.ver, rec.ver)) {
            .same, .older, .conflict_stored_wins => return .ignore,
            else => {},
        }
        // Newer/conflict-winner: identical content needs no transfer.
        if (rec.state == .live and std.mem.eql(u8, &rec.sha256, &entry.sha256))
            return .adopt;
        return .fetch;
    }
    return .fetch;
}

// ---- tests ----

const t = std.testing;

const Rig = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    state: []u8,

    fn make(alloc: Allocator) !Rig {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const base = try tmp.dir.realpathAlloc(alloc, ".");
        defer alloc.free(base);
        const root = try std.fs.path.join(alloc, &.{ base, "root" });
        const state = try std.fs.path.join(alloc, &.{ base, "state" });
        try std.fs.cwd().makePath(root);
        try std.fs.cwd().makePath(state);
        return .{ .tmp = tmp, .root = root, .state = state };
    }
    fn destroy(self: *Rig, alloc: Allocator) void {
        alloc.free(self.root);
        alloc.free(self.state);
        self.tmp.cleanup();
    }
    fn write(self: *Rig, alloc: Allocator, rel: []const u8, data: []const u8) !void {
        const abs = try std.fs.path.join(alloc, &.{ self.root, rel });
        defer alloc.free(abs);
        if (std.fs.path.dirname(abs)) |d| try std.fs.cwd().makePath(d);
        try std.fs.cwd().writeFile(.{ .sub_path = abs, .data = data });
    }
    fn remove(self: *Rig, alloc: Allocator, rel: []const u8) !void {
        const abs = try std.fs.path.join(alloc, &.{ self.root, rel });
        defer alloc.free(abs);
        std.fs.cwd().deleteFile(abs) catch {};
    }
};

fn drainJournal(j: *journal.Journal) []journal.Work {
    var out: std.ArrayList(journal.Work) = .empty;
    j.collectReady(std.math.maxInt(i64) - 1, &out) catch unreachable;
    return out.toOwnedSlice(t.allocator) catch unreachable;
}

test "first scan announces the seeded tree" {
    const alloc = t.allocator;
    var rig = try Rig.make(alloc);
    defer rig.destroy(alloc);
    try rig.write(alloc, "a.txt", "aaa");
    try rig.write(alloc, "sub/b.txt", "bbb");

    var cs = try contentset.ContentSet.open(alloc, rig.state, "test");
    defer cs.close();
    var j = journal.Journal.init(alloc, 10);
    defer j.deinit();

    const stats = try scan(alloc, rig.root, &cs, &j, 0);
    try t.expectEqual(@as(u64, 3), stats.seen); // a.txt, sub, sub/b.txt
    try t.expectEqual(@as(u64, 3), stats.announced_new);
    try t.expectEqual(@as(usize, 3), j.pendingCount());
    try t.expect(cs.dirPath(cs.lookup("sub").?.id.fsid, cs.lookup("sub").?.id.fileid) != null);

    const works = drainJournal(&j);
    defer {
        for (works) |*w| j.freeWork(w);
        t.allocator.free(works);
    }
    try t.expectEqual(@as(usize, 3), works.len);
}

test "clean restart scan announces nothing" {
    const alloc = t.allocator;
    var rig = try Rig.make(alloc);
    defer rig.destroy(alloc);
    try rig.write(alloc, "a.txt", "aaa");

    {
        var cs = try contentset.ContentSet.open(alloc, rig.state, "test");
        var j = journal.Journal.init(alloc, 10);
        defer j.deinit();
        _ = try scan(alloc, rig.root, &cs, &j, 0);
        var works: std.ArrayList(journal.Work) = .empty;
        j.collectReady(std.math.maxInt(i64) - 1, &works) catch unreachable;
        const w2 = works.toOwnedSlice(alloc) catch unreachable;
        for (w2) |*w| j.freeWork(w);
        alloc.free(w2);
        try cs.snapshot();
        cs.close();
    }
    {
        var cs = try contentset.ContentSet.open(alloc, rig.state, "test");
        defer cs.close();
        var j = journal.Journal.init(alloc, 10);
        defer j.deinit();
        const stats = try scan(alloc, rig.root, &cs, &j, 0);
        try t.expectEqual(@as(u64, 0), stats.announced_new);
        try t.expectEqual(@as(u64, 0), stats.announced_modified);
        try t.expectEqual(@as(u64, 0), stats.announced_deleted);
        try t.expectEqual(@as(u64, 1), stats.unchanged);
        try t.expectEqual(@as(usize, 0), j.pendingCount());
    }
}

test "offline modify, create, and delete are caught" {
    const alloc = t.allocator;
    var rig = try Rig.make(alloc);
    defer rig.destroy(alloc);
    try rig.write(alloc, "mod.txt", "before");
    try rig.write(alloc, "del.txt", "gone soon");

    {
        var cs = try contentset.ContentSet.open(alloc, rig.state, "test");
        var j = journal.Journal.init(alloc, 10);
        defer j.deinit();
        _ = try scan(alloc, rig.root, &cs, &j, 0);
        var works: std.ArrayList(journal.Work) = .empty;
        j.collectReady(std.math.maxInt(i64) - 1, &works) catch unreachable;
        const w2 = works.toOwnedSlice(alloc) catch unreachable;
        for (w2) |*w| j.freeWork(w);
        alloc.free(w2);
        try cs.snapshot();
        cs.close();
    }

    // Daemon down: modify one, delete one, create one.
    // (mtime granularity: force a difference even on coarse filesystems)
    try rig.write(alloc, "mod.txt", "after: longer content");
    try rig.remove(alloc, "del.txt");
    try rig.write(alloc, "new.txt", "brand new");

    var cs = try contentset.ContentSet.open(alloc, rig.state, "test");
    defer cs.close();
    var j = journal.Journal.init(alloc, 10);
    defer j.deinit();
    const stats = try scan(alloc, rig.root, &cs, &j, 0);
    try t.expectEqual(@as(u64, 1), stats.announced_new);
    try t.expectEqual(@as(u64, 1), stats.announced_modified);
    try t.expectEqual(@as(u64, 1), stats.announced_deleted);
    try t.expectEqual(contentset.State.deleted, cs.lookup("del.txt").?.state);
}

test "file resurrecting over a tombstone gets a fresh local version" {
    const alloc = t.allocator;
    var rig = try Rig.make(alloc);
    defer rig.destroy(alloc);

    var cs = try contentset.ContentSet.open(alloc, rig.state, "test");
    defer cs.close();
    // Pre-seed a tombstone for a path that exists on disk.
    var rec = contentset.Record{ .state = .deleted, .ver = .{ .origin = 42, .seq = 7 } };
    rec.sha256 = [_]u8{0} ** 32;
    try cs.upsert("ghost.txt", rec);
    try rig.write(alloc, "ghost.txt", "i am back");

    var j = journal.Journal.init(alloc, 10);
    defer j.deinit();
    const stats = try scan(alloc, rig.root, &cs, &j, 0);
    try t.expectEqual(@as(u64, 1), stats.announced_new);
    const after = cs.lookup("ghost.txt").?;
    try t.expectEqual(contentset.State.live, after.state);
    try t.expectEqual(cs.local_origin, after.ver.origin);
}

test "version vector covers and filters" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);

    var cs = try contentset.ContentSet.open(alloc, dir, "test");
    defer cs.close();
    var r1 = contentset.Record{ .ver = .{ .origin = 1, .seq = 5 } };
    try cs.upsert("a", r1);
    r1.ver = .{ .origin = 2, .seq = 9 };
    try cs.upsert("b", r1);
    r1.ver = .{ .origin = 1, .seq = 12 };
    try cs.upsert("c", r1);

    const vec = buildVector(&cs);
    try t.expectEqual(@as(u16, 2), vec.count);
    try t.expect(vectorCovers(&vec, .{ .origin = 1, .seq = 12 }));
    try t.expect(vectorCovers(&vec, .{ .origin = 1, .seq = 3 }));
    try t.expect(!vectorCovers(&vec, .{ .origin = 1, .seq = 13 }));
    try t.expect(!vectorCovers(&vec, .{ .origin = 3, .seq = 1 }));
}

test "entryAction matrix" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(dir);

    var cs = try contentset.ContentSet.open(alloc, dir, "test");
    defer cs.close();
    const sha = [_]u8{9} ** 32;
    try cs.upsert("same", .{ .ver = .{ .origin = 1, .seq = 2 }, .sha256 = sha });
    try cs.upsert("older", .{ .ver = .{ .origin = 1, .seq = 2 }, .sha256 = sha });

    const base = protocol.ResyncEntry{
        .ver = .{ .origin = 1, .seq = 2 },
        .is_dir = false,
        .state = .live,
        .mode = 0o644,
        .size = 1,
        .mtime_sec = 0,
        .mtime_nsec = 0,
        .path = "same",
        .sha256 = sha,
    };
    try t.expectEqual(EntryAction.ignore, entryAction(&cs, base)); // same ver
    var newer = base;
    newer.ver.seq = 3;
    try t.expectEqual(EntryAction.adopt, entryAction(&cs, newer)); // same sha
    var diff = base;
    diff.ver.seq = 3;
    diff.sha256 = [_]u8{1} ** 32;
    try t.expectEqual(EntryAction.fetch, entryAction(&cs, diff)); // content differs
    var unknown = base;
    unknown.path = "unknown";
    try t.expectEqual(EntryAction.fetch, entryAction(&cs, unknown));
    var tomb = base;
    tomb.state = .deleted;
    tomb.ver.seq = 3;
    try t.expectEqual(EntryAction.tombstone, entryAction(&cs, tomb));
    tomb.path = "unknown";
    try t.expectEqual(EntryAction.tombstone, entryAction(&cs, tomb));
    tomb.ver = .{ .origin = 1, .seq = 1 }; // older than stored
    tomb.path = "same";
    try t.expectEqual(EntryAction.ignore, entryAction(&cs, tomb));
}
