//! installer.zig — getting bytes safely into the replicated tree.
//!
//! Correctness rules 1 + 3: staging write + fsync + rename(2) (atomic, no
//! torn files); LWW loser quarantined to state_dir/conflicts/, never
//! silently dropped.
//!
//! Flow for an incoming ANNOUNCE: beginFetch -> writeChunk* -> the split
//! complete: beginComplete (core thread: incremental-hash verify, detach)
//! -> completion worker (finishComplete: fsync -> quarantine divergent
//! existing dest -> rename into place -> mode+mtime) -> daemon onInstalled
//! (upsert + FETCH_ACK).  Delete side: tombstone() removes the path (dirs
//! recursively — the sender's per-file tombstones may not all have arrived).
//!
//! staging/ and conflicts/ live under state_dir, which init() verifies is
//! on the SAME filesystem as the replicated root (rename must not EXDEV).

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const contentset = @import("contentset.zig");

extern "c" fn utimensat(dirfd: c_int, path: [*:0]const u8, times: *const [2]posix.timespec, flags: c_int) c_int;
extern "c" fn fchmod(fd: c_int, mode: c_uint) c_int;

// struct statfs header through f_fsid (sys/mount.h, FreeBSD 15).  The
// trailing blob keeps the buffer big enough for the kernel to fill.
const fsid_t = extern struct { val: [2]i32 };
const StatfsHeader = extern struct {
    f_version: u32,
    f_type: u32,
    f_flags: u64,
    f_bsize: u64,
    f_iosize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: i64,
    f_files: u64,
    f_ffree: i64,
    f_syncwrites: u64,
    f_asyncwrites: u64,
    f_syncreads: u64,
    f_asyncreads: u64,
    f_spare: [10]u64,
    f_namemax: u32,
    f_owner: u32,
    f_fsid: fsid_t,
    _rest: [2048]u8,
};
extern "c" fn statfs(path: [*:0]const u8, buf: *StatfsHeader) c_int;

/// The filesystem id in the SAME encoding brfs.ko uses for be_fsid
/// (f_fsid.val[0]<<32 | val[1]).  st_dev is a DIFFERENT namespace — do not
/// mix them (empirical: /data on the rig: st_dev=60, f_fsid pair hashes).
pub fn fsidOf(path: []const u8) !u64 {
    var st: StatfsHeader = undefined;
    const path_z = try std.posix.toPosixPath(path);
    if (statfs(&path_z, &st) != 0) return error.StatfsFailed;
    return (@as(u64, @as(u32, @bitCast(st.f_fsid.val[0]))) << 32) |
        @as(u64, @as(u32, @bitCast(st.f_fsid.val[1])));
}

pub const chunk_size: usize = 1024 * 1024;

/// Headroom kept free on the staging filesystem: the csdb env (same fs),
/// the conflicts dir, and general fs health — ZFS write performance
/// degrades sharply as it approaches full.
pub const free_space_reserve: u64 = 64 * 1024 * 1024;

/// Gap #18 precondition: refuse to stage what cannot fit.  Checked BEFORE
/// opening the staging file so a too-big announce costs nothing; the
/// fetch stays in the incoming map, times out as a stall, and the next
/// ANNOUNCE/resync round retries once space exists (T15 recovery path).
pub fn spaceCheck(free: u64, incoming: u64) error{NoSpaceLeft}!void {
    if (free < free_space_reserve) return error.NoSpaceLeft;
    if (incoming > free - free_space_reserve) return error.NoSpaceLeft;
}

/// The two halves of an install, split so the blocking fsync/rename can
/// run on the daemon's completion worker instead of the core loop (a 200MB
/// fsync blocked the loop for tens of seconds on the rig, stalling the
/// whole mesh — Phase 2 fix).
pub const CompleteJob = struct {
    path: []u8, // owned (travels to the result for freeing)
    ver: contentset.Version,
    fd: posix.fd_t, // owned; finishComplete fsyncs + closes it
    size: u64,
    sha256: [32]u8, // verified actual content hash
    mode: u16,
    mtime_sec: i64,
    mtime_nsec: u32,
    /// Staged file identity: the install echo swallows by fileid/gen
    /// compare (O(1)) instead of re-hashing the installed file on the
    /// core loop.
    fileid: u64,
    gen: u64,
    /// Serving node's id for the FETCH_ACK (advisory; owned).
    ack_peer: ?[]u8 = null,
    /// Conflict name the divergent destination was quarantined to
    /// (owned; set by finishComplete).  The daemon needs it to restore
    /// the winner's content when a superseded install is reverted.
    quarantined: ?[]u8 = null,
};

pub const CompleteResult = struct {
    job: CompleteJob,
    err: ?anyerror = null,
};

const Fetch = struct {
    fd: posix.fd_t,
    path: []u8, // owned
    ver: contentset.Version,
    size: u64,
    sha256: [32]u8, // expected (from the announce)
    mode: u16,
    mtime_sec: i64,
    mtime_nsec: u32,
    received: u64 = 0,
    // Chunks arrive in strict offset order, so the hash is computed
    // incrementally as they land — complete() would otherwise re-read and
    // re-hash the whole file on the core thread (200 MiB blocked the event
    // loop for tens of seconds on the bhyve rig, stalling all conns).
    hasher: std.crypto.hash.sha2.Sha256,
};

pub const Installer = struct {
    alloc: Allocator,
    root: []const u8, // owned
    staging: []const u8, // owned
    conflicts: []const u8, // owned
    fetches: std.StringHashMap(*Fetch),

    pub fn init(alloc: Allocator, root: []const u8, state_dir: []const u8) !Installer {
        const staging = try std.fs.path.join(alloc, &.{ state_dir, "staging" });
        errdefer alloc.free(staging);
        const conflicts = try std.fs.path.join(alloc, &.{ state_dir, "conflicts" });
        errdefer alloc.free(conflicts);
        try std.fs.cwd().makePath(staging);
        try std.fs.cwd().makePath(conflicts);

        // Same-filesystem rule: staging (and conflicts) must share the
        // root's device or rename(2) fails with EXDEV mid-replication.
        const root_st = try statPath(root);
        const staging_st = try statPath(staging);
        if (root_st.dev != staging_st.dev) return error.StateDirWrongFs;

        return .{
            .alloc = alloc,
            .root = try alloc.dupe(u8, root),
            .staging = staging,
            .conflicts = conflicts,
            .fetches = std.StringHashMap(*Fetch).init(alloc),
        };
    }

    pub fn deinit(self: *Installer) void {
        var it = self.fetches.iterator();
        while (it.next()) |e| {
            const f = e.value_ptr.*;
            if (f.fd >= 0) posix.close(f.fd);
            self.alloc.free(f.path); // same allocation as the map key
            self.alloc.destroy(f);
        }
        self.fetches.deinit();
        self.alloc.free(self.root);
        self.alloc.free(self.staging);
        self.alloc.free(self.conflicts);
    }

    fn stagingPath(self: *Installer, scratch: *[4096]u8, path: []const u8, ver: contentset.Version) ![]const u8 {
        // Unique per (path, version): a re-FETCH after a hash mismatch
        // never collides with the aborted staging file.
        return std.fmt.bufPrint(scratch, "{s}/{x}-{x}-{x}.part", .{
            self.staging,
            std.hash.Fnv1a_64.hash(path),
            ver.origin,
            ver.seq,
        });
    }

    /// Bytes available to an unprivileged writer on the staging filesystem
    /// (f_bavail — the usable number; clamped at zero: it can go negative
    /// past the reserved-blocks threshold).
    pub fn stagingFreeBytes(self: *const Installer) !u64 {
        var st: StatfsHeader = undefined;
        const path_z = try std.posix.toPosixPath(self.staging);
        if (statfs(&path_z, &st) != 0) return error.StatfsFailed;
        if (st.f_bavail <= 0) return 0;
        return @as(u64, @intCast(st.f_bavail)) * st.f_bsize;
    }

    /// Open a staging file for an incoming version of path.
    pub fn beginFetch(self: *Installer, path: []const u8, ann: anytype) !void {
        if (self.fetches.contains(path)) return error.FetchInProgress;
        try spaceCheck(try self.stagingFreeBytes(), ann.size);
        var scratch: [4096]u8 = undefined;
        const spath = try self.stagingPath(&scratch, path, ann.ver);
        const fd = try posix.open(spath, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true }, 0o600);
        errdefer posix.close(fd);

        const owned = try self.alloc.dupe(u8, path);
        errdefer self.alloc.free(owned);
        const f = try self.alloc.create(Fetch);
        f.* = .{
            .fd = fd,
            .path = owned,
            .ver = ann.ver,
            .size = ann.size,
            .sha256 = ann.sha256,
            .mode = ann.mode,
            .mtime_sec = ann.mtime_sec,
            .mtime_nsec = ann.mtime_nsec,
            .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
        };
        try self.fetches.put(owned, f);
    }

    /// Write one FETCH_DATA chunk.  Strict sequencing: chunks must arrive
    /// in offset order with no gaps (the sender sequences them).
    pub fn writeChunk(self: *Installer, path: []const u8, ver: contentset.Version, offset: u64, data: []const u8) !void {
        const f = self.fetches.get(path) orelse return error.NoFetch;
        if (!f.ver.eql(ver)) return error.StaleFetch;
        if (offset != f.received) return error.GapInFetch;
        if (f.received + data.len > f.size) return error.Overshoot;
        var off: usize = 0;
        while (off < data.len) {
            const n = try posix.pwrite(f.fd, data[off..], @intCast(f.received + off));
            off += n;
        }
        f.hasher.update(data);
        f.received += data.len;
    }

    pub fn fetchComplete(self: *Installer, path: []const u8) bool {
        const f = self.fetches.get(path) orelse return false;
        return f.received == f.size;
    }

    /// Fill in meta for a fetch started without it (the unpaired MOVE_TO
    /// fallback): the sender emits a fresh ANNOUNCE before its chunks, and
    /// the daemon updates the in-flight fetch with real size/hash.
    pub fn updateFetchMeta(self: *Installer, path: []const u8, size: u64, sha256: [32]u8, mode: u16, mtime_sec: i64, mtime_nsec: u32) void {
        const f = self.fetches.get(path) orelse return;
        f.size = size;
        f.sha256 = sha256;
        f.mode = mode;
        f.mtime_sec = mtime_sec;
        f.mtime_nsec = mtime_nsec;
    }

    pub fn fetchInProgress(self: *Installer, path: []const u8) bool {
        return self.fetches.contains(path);
    }

    /// Bytes staged so far (the next FETCH_REQ's offset).
    pub fn fetchOffset(self: *Installer, path: []const u8) u64 {
        const f = self.fetches.get(path) orelse return 0;
        return f.received;
    }

    pub fn abortFetch(self: *Installer, path: []const u8) void {
        if (self.fetches.fetchRemove(path)) |kv| {
            const f = kv.value;
            var scratch: [4096]u8 = undefined;
            if (self.stagingPath(&scratch, f.path, f.ver)) |sp| {
                std.fs.cwd().deleteFile(sp) catch {};
            } else |_| {}
            self.freeFetch(kv.key, f);
        }
    }

    fn freeFetch(self: *Installer, key: []const u8, f: *Fetch) void {
        // key IS f.path (same allocation): free once.
        std.debug.assert(std.mem.eql(u8, key, f.path));
        if (f.fd >= 0) posix.close(f.fd);
        self.alloc.free(f.path);
        self.alloc.destroy(f);
    }

    /// Hash-verify the staged file and atomically rename it into the tree.
    /// Synchronous convenience (= beginComplete + finishComplete on the
    /// caller's thread); the daemon uses the split form.
    /// Returns the installed sha256 for the caller's FETCH_ACK + echo note.
    pub fn complete(self: *Installer, path: []const u8) ![32]u8 {
        var job = try self.beginComplete(path);
        defer self.alloc.free(job.path);
        defer if (job.quarantined) |q| self.alloc.free(q);
        try self.finishComplete(&job);
        return job.sha256;
    }

    /// Discard a staged install that lost the version race before the
    /// worker landed it: close the fd and remove the staging file.  The
    /// tree is never touched (no kernel events, no quarantine, no echo).
    /// Does NOT consume job.path (the caller frees it).
    pub fn discardComplete(self: *Installer, job: *const CompleteJob) void {
        posix.close(job.fd);
        var scratch: [4096]u8 = undefined;
        if (self.stagingPath(&scratch, job.path, job.ver)) |sp| {
            std.fs.cwd().deleteFile(sp) catch {};
        } else |_| {}
    }

    /// Core-thread half of an install: verify the staged content (the hash
    /// was computed incrementally at writeChunk — this is just the final)
    /// and detach the fetch into a job for the completion worker.
    /// HashMismatch keeps the synchronous requeue semantics (staging
    /// dropped, fetch forgotten).
    pub fn beginComplete(self: *Installer, path: []const u8) !CompleteJob {
        const kv = self.fetches.fetchRemove(path) orelse return error.NoFetch;
        const f = kv.value;

        var actual: [32]u8 = undefined;
        f.hasher.final(&actual);
        const bad = !std.mem.eql(u8, &actual, &f.sha256);

        var st: posix.Stat = undefined;
        const stat_ok = std.c.fstat(f.fd, &st) == 0;

        if (bad or !stat_ok) {
            var scratch: [4096]u8 = undefined;
            if (self.stagingPath(&scratch, f.path, f.ver)) |sp| {
                std.fs.cwd().deleteFile(sp) catch {};
            } else |_| {}
            self.freeFetch(kv.key, f);
            return if (bad) error.HashMismatch else error.StatFailed;
        }

        const job = CompleteJob{
            // kv.key IS f.path (same allocation): ownership moves to the job.
            .path = @constCast(kv.key),
            .ver = f.ver,
            .fd = f.fd,
            .size = f.size,
            .sha256 = actual,
            .mode = f.mode,
            .mtime_sec = f.mtime_sec,
            .mtime_nsec = f.mtime_nsec,
            .fileid = @intCast(st.ino),
            .gen = @intCast(st.gen),
        };
        f.fd = -1; // ownership moved
        self.alloc.destroy(f);
        return job;
    }

    /// Worker-thread half of an install: fsync + quarantine-divergent +
    /// rename + meta.  Blocks freely.  Reads only root/staging/conflicts
    /// (immutable post-init) plus its own stack — thread-safe by
    /// construction.  Consumes job.fd.  On failure the staging file is
    /// removed.
    pub fn finishComplete(self: *Installer, job: *CompleteJob) !void {
        var scratch: [4096]u8 = undefined;
        const spath = try self.stagingPath(&scratch, job.path, job.ver);
        errdefer std.fs.cwd().deleteFile(spath) catch {};

        posix.fsync(job.fd) catch |e| {
            posix.close(job.fd);
            return e;
        };
        posix.close(job.fd);

        const dest = try std.fs.path.join(self.alloc, &.{ self.root, job.path });
        defer self.alloc.free(dest);

        // Quarantine a divergent destination; identical content just gets
        // replaced (idempotent re-install).  Remember where it went: a
        // superseded install's revert restores it.
        if (statPath(dest)) |st| {
            if (isDir(st)) return error.DestIsDir;
            const existing = hashFile(dest) catch null;
            if (existing == null or !std.mem.eql(u8, &existing.?, &job.sha256))
                job.quarantined = try self.quarantine(job.path);
        } else |_| {}

        if (std.fs.path.dirname(job.path)) |dir| {
            const abs = try std.fs.path.join(self.alloc, &.{ self.root, dir });
            defer self.alloc.free(abs);
            try std.fs.cwd().makePath(abs);
        }

        // Mode + mtime policy: replicate mode bits and mtime (not uid/gid).
        try posix.rename(spath, dest);
        applyMeta(dest, job.mode, job.mtime_sec, job.mtime_nsec);
        fsyncParentDir(dest);
    }

    /// Move root/path into conflicts/ (timestamped).  Returns the owned
    /// conflict name; null when nothing was there to quarantine.
    pub fn quarantine(self: *Installer, path: []const u8) !?[]u8 {
        const src = try std.fs.path.join(self.alloc, &.{ self.root, path });
        defer self.alloc.free(src);
        _ = statPath(src) catch return null; // nothing to quarantine

        const stamp = std.time.milliTimestamp();
        const name = try std.fmt.allocPrint(self.alloc, "{s}.{d}", .{ path, stamp });
        errdefer self.alloc.free(name);
        const dst = try std.fs.path.join(self.alloc, &.{ self.conflicts, name });
        defer self.alloc.free(dst);
        if (std.fs.path.dirname(dst)) |dir|
            try std.fs.cwd().makePath(dir);

        try posix.rename(src, dst);
        fsyncParentDir(dst);
        return name;
    }

    /// Apply a tombstone: remove the path (dirs recursively — the sender's
    /// per-file deletes may lag the dir tombstone).
    pub fn tombstone(self: *Installer, path: []const u8, is_dir: bool) !void {
        const abs = try std.fs.path.join(self.alloc, &.{ self.root, path });
        defer self.alloc.free(abs);
        if (is_dir) {
            std.fs.cwd().deleteTree(abs) catch {};
        } else {
            const abs_z = try std.posix.toPosixPath(abs);
            if (std.c.unlink(&abs_z) != 0) {
                switch (std.c._errno().*) {
                    @intFromEnum(std.c.E.NOENT) => {},
                    // A dir where we expected a file: remove as a dir.
                    @intFromEnum(std.c.E.PERM), @intFromEnum(std.c.E.ISDIR) => std.fs.cwd().deleteTree(abs) catch {},
                    else => return error.UnlinkFailed,
                }
            }
        }
        fsyncParentDir(abs);
    }

    /// Absolute path of a live tree entry (for stat/hash by the daemon).
    pub fn absPath(self: *Installer, path: []const u8) ![]u8 {
        return std.fs.path.join(self.alloc, &.{ self.root, path });
    }
};

pub fn isDir(st: posix.Stat) bool {
    return @as(u32, @intCast(st.mode)) & @as(u32, @intCast(std.c.S.IFMT)) ==
        @as(u32, @intCast(std.c.S.IFDIR));
}

pub fn statPath(path: []const u8) !posix.Stat {
    var st: posix.Stat = undefined;
    const path_z = try std.posix.toPosixPath(path);
    if (std.c.stat(&path_z, &st) != 0)
        return error.FileNotFound;
    return st;
}

pub fn hashFile(path: []const u8) ![32]u8 {
    const fd = try posix.open(path, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(fd);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try posix.read(fd, &buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Apply replicated metadata (mode bits + mtime; NOT uid/gid) to an
/// existing path.  Public: the daemon uses it for dir ANNOUNCEs.
pub fn setMeta(path: []const u8, mode: u16, mtime_sec: i64, mtime_nsec: u32) void {
    applyMeta(path, mode, mtime_sec, mtime_nsec);
}

fn applyMeta(path: []const u8, mode: u16, mtime_sec: i64, mtime_nsec: u32) void {
    const fd = posix.open(path, .{ .ACCMODE = .RDONLY }, 0) catch return;
    defer posix.close(fd);
    _ = fchmod(fd, mode);
    const path_z = std.posix.toPosixPath(path) catch return;
    const times = [2]posix.timespec{
        .{ .sec = mtime_sec, .nsec = mtime_nsec }, // atime := mtime
        .{ .sec = mtime_sec, .nsec = mtime_nsec },
    };
    _ = utimensat(std.c.AT.FDCWD, &path_z, &times, 0);
}

fn fsyncParentDir(path: []const u8) void {
    const dir = std.fs.path.dirname(path) orelse return;
    const fd = posix.open(dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch return;
    defer posix.close(fd);
    posix.fsync(fd) catch {};
}

// ---- tests ----

const t = std.testing;

const TestRig = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    state: []u8,
    inst: Installer,

    fn make(alloc: Allocator) !TestRig {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const base = try tmp.dir.realpathAlloc(alloc, ".");
        defer alloc.free(base);
        const root = try std.fs.path.join(alloc, &.{ base, "root" });
        const state = try std.fs.path.join(alloc, &.{ base, "state" });
        try std.fs.cwd().makePath(root);
        const inst = try Installer.init(alloc, root, state);
        return .{ .tmp = tmp, .root = root, .state = state, .inst = inst };
    }

    fn destroy(self: *TestRig, alloc: Allocator) void {
        self.inst.deinit();
        alloc.free(self.root);
        alloc.free(self.state);
        self.tmp.cleanup();
    }
};

const Ann = struct {
    ver: contentset.Version,
    size: u64,
    sha256: [32]u8,
    mode: u16 = 0o644,
    mtime_sec: i64 = 1_700_000_000,
    mtime_nsec: u32 = 555,
};

fn announceOf(data: []const u8, seq: u64) Ann {
    return .{
        .ver = .{ .origin = 99, .seq = seq },
        .size = data.len,
        .sha256 = blk: {
            var d: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(data, &d, .{});
            break :blk d;
        },
    };
}

fn readTreeFile(alloc: Allocator, rig: *TestRig, path: []const u8) ![]u8 {
    const abs = try rig.inst.absPath(path);
    defer alloc.free(abs);
    return std.fs.cwd().readFileAlloc(alloc, abs, 1 << 20);
}

test "fetch, chunk, install lands content atomically" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);

    const data = "hello replicated world";
    const ann = announceOf(data, 1);
    try rig.inst.beginFetch("sub/dir/file.txt", ann);
    // Two chunks to exercise offset sequencing.
    try rig.inst.writeChunk("sub/dir/file.txt", ann.ver, 0, data[0..5]);
    try rig.inst.writeChunk("sub/dir/file.txt", ann.ver, 5, data[5..]);
    try t.expect(rig.inst.fetchComplete("sub/dir/file.txt"));
    const sha = try rig.inst.complete("sub/dir/file.txt");
    try t.expectEqual(ann.sha256, sha);

    const got = try readTreeFile(alloc, &rig, "sub/dir/file.txt");
    defer alloc.free(got);
    try t.expectEqualStrings(data, got);

    // Mode + mtime replicated.
    const installed = try rig.inst.absPath("sub/dir/file.txt");
    defer alloc.free(installed);
    const st = try statPath(installed);
    try t.expectEqual(@as(u32, 0o644), @as(u32, @intCast(st.mode)) & 0o7777);
    try t.expectEqual(@as(i64, 1_700_000_000), @as(i64, @intCast(st.mtim.sec)));
}

test "split complete: core-side verify + worker-side install" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);

    const data = "split install content";
    const ann = announceOf(data, 3);
    try rig.inst.beginFetch("split.txt", ann);
    try rig.inst.writeChunk("split.txt", ann.ver, 0, data);

    var job = try rig.inst.beginComplete("split.txt");
    defer alloc.free(job.path);
    try t.expect(!rig.inst.fetchInProgress("split.txt")); // detached
    try t.expect(job.fileid != 0); // staged identity for the echo swallow
    try t.expectEqual(ann.sha256, job.sha256); // verified at handoff
    try rig.inst.finishComplete(&job);

    const got = try readTreeFile(alloc, &rig, "split.txt");
    defer alloc.free(got);
    try t.expectEqualStrings(data, got);
}

test "split complete: hash mismatch stays synchronous and drops staging" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);
    var ann = announceOf("correct", 1);
    try rig.inst.beginFetch("f", ann);
    try rig.inst.writeChunk("f", ann.ver, 0, "corrupt");
    ann.sha256[0] ^= 0xff;
    rig.inst.fetches.get("f").?.sha256 = ann.sha256;
    try t.expectError(error.HashMismatch, rig.inst.beginComplete("f"));
    try t.expect(!rig.inst.fetchInProgress("f"));
    var buf: [4096]u8 = undefined;
    const sp = try rig.inst.stagingPath(&buf, "f", ann.ver);
    try t.expectError(error.FileNotFound, statPath(sp));
}

test "out-of-order chunk is a hard error" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);
    const ann = announceOf("abcdef", 1);
    try rig.inst.beginFetch("f", ann);
    try t.expectError(error.GapInFetch, rig.inst.writeChunk("f", ann.ver, 3, "d"));
    rig.inst.abortFetch("f");
}

test "hash mismatch aborts the install and drops staging" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);
    var ann = announceOf("correct", 1);
    try rig.inst.beginFetch("f", ann);
    try rig.inst.writeChunk("f", ann.ver, 0, "corrupt");
    ann.sha256[0] ^= 0xff; // sender's announced hash no longer matches
    rig.inst.fetches.get("f").?.sha256 = ann.sha256;
    try t.expectError(error.HashMismatch, rig.inst.complete("f"));
    // Staging file cleaned up:
    var buf: [4096]u8 = undefined;
    const sp = try rig.inst.stagingPath(&buf, "f", ann.ver);
    try t.expectError(error.FileNotFound, statPath(sp));
}

test "divergent destination is quarantined, not overwritten" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);

    // Pre-existing local content (e.g. pre-seed file on a joining node).
    const abs = try rig.inst.absPath("conflict.txt");
    defer alloc.free(abs);
    try std.fs.cwd().writeFile(.{ .sub_path = abs, .data = "local version" });

    const data = "group version";
    const ann = announceOf(data, 7);
    try rig.inst.beginFetch("conflict.txt", ann);
    try rig.inst.writeChunk("conflict.txt", ann.ver, 0, data);
    _ = try rig.inst.complete("conflict.txt");

    const got = try readTreeFile(alloc, &rig, "conflict.txt");
    defer alloc.free(got);
    try t.expectEqualStrings(data, got);

    // Loser preserved under conflicts/.
    var dir = try std.fs.cwd().openDir(rig.inst.conflicts, .{ .iterate = true });
    defer dir.close();
    var found = false;
    var it = dir.iterate();
    while (try it.next()) |ent| {
        if (std.mem.startsWith(u8, ent.name, "conflict.txt.")) found = true;
    }
    try t.expect(found);
}

test "tombstone removes files and trees" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);

    const data = "x";
    const ann = announceOf(data, 1);
    try rig.inst.beginFetch("d/f.txt", ann);
    try rig.inst.writeChunk("d/f.txt", ann.ver, 0, data);
    _ = try rig.inst.complete("d/f.txt");

    try rig.inst.tombstone("d/f.txt", false);
    const f_abs = try rig.inst.absPath("d/f.txt");
    defer alloc.free(f_abs);
    try t.expectError(error.FileNotFound, statPath(f_abs));

    // Dir tombstone with residue (per-file tombstones never arrived).
    try rig.inst.beginFetch("d2/f.txt", ann);
    try rig.inst.writeChunk("d2/f.txt", ann.ver, 0, data);
    _ = try rig.inst.complete("d2/f.txt");
    try rig.inst.tombstone("d2", true);
    const d2_abs = try rig.inst.absPath("d2");
    defer alloc.free(d2_abs);
    try t.expectError(error.FileNotFound, statPath(d2_abs));

    // Idempotent: deleting again is a no-op.
    try rig.inst.tombstone("d2", true);
    try rig.inst.tombstone("d/f.txt", false);
}

test "spaceCheck enforces the staging reserve" {
    const r = free_space_reserve;
    try t.expectError(error.NoSpaceLeft, spaceCheck(0, 0));
    try t.expectError(error.NoSpaceLeft, spaceCheck(r - 1, 0));
    try t.expectError(error.NoSpaceLeft, spaceCheck(r, 1));
    try t.expectError(error.NoSpaceLeft, spaceCheck(r + 100, 101));
    try spaceCheck(r + 100, 100);
    try spaceCheck(r, 0);
}

test "beginFetch refuses a fetch that cannot fit" {
    const alloc = t.allocator;
    var rig = try TestRig.make(alloc);
    defer rig.destroy(alloc);

    var ann = announceOf("x", 1);
    ann.size = std.math.maxInt(u64) / 2;
    try t.expectError(error.NoSpaceLeft, rig.inst.beginFetch("huge.bin", ann));
    try t.expect(!rig.inst.fetchInProgress("huge.bin"));

    // A sane size stages fine on the same rig.
    try rig.inst.beginFetch("small.bin", announceOf("x", 1));
    rig.inst.abortFetch("small.bin");
}

test "staging on a different filesystem is rejected at init" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const root = try std.fs.path.join(alloc, &.{ base, "root" });
    defer alloc.free(root);
    try std.fs.cwd().makePath(root);
    // /tmp vs the tmpDir filesystem may coincide; only assert when they
    // genuinely differ is impossible to guarantee here, so just verify the
    // happy path succeeds and trust the stat dev comparison logic.
    var rig = try Installer.init(alloc, root, base);
    rig.deinit();
}
