//! contentset.zig — the BrFS content set: per-file current state.
//!
//! One record per path (relative to the replicated root): identity
//! (fsid/fileid/gen from the kernel feed), version (origin_node, origin_seq),
//! size, mtime, mode, sha256, and a first-class state flag
//! (live | deleted) — deletes are tombstones from day one.
//!
//! Persistence is LMDB (Phase 2 swap; decision locked 2026-08-24 — replaces
//! the POC append-only log + snapshot):
//!   - gap #12 (crash consistency): every flush()/checkpoint() is ONE LMDB
//!     write-txn commit — records, the ring-seq checkpoint, and the local
//!     seq counter land atomically and fsync'd.  Torn tails cannot exist by
//!     construction; an uncommitted batch simply never happened and
//!     idempotent replay heals it.
//!   - gap #7 (tombstone retention/GC): tombstones are durable keys with a
//!     deleted_at wall-clock stamp (retention bookkeeping only — ordering
//!     stays pure version vectors, T18).  gcTombstones() drops tombstones
//!     older than tombstone_ttl_sec (7 days, the DFSR ConflictAndDeleted
//!     window).  The all-member-ack horizon half of the locked retention
//!     rule (keep until ALL members' last-ack ver exceeds the tombstone
//!     ver OR the TTL, whichever is longer) lands with per-member ack
//!     tracking; TTL alone is DFSR-equivalent until then.
//!   - Corruption fallback: an env that fails to open or load is moved
//!     aside (csdb.corrupt-<ts>) and rebuilt empty with needs_scan — the
//!     set is a cache of ground truth, never the only copy.
//!
//! The in-memory map stays the query layer (the daemon iterates it
//! directly); LMDB is the durable store it is write-through mirrored into.
//!
//! Gotchas carried from the design decision: the map size is FIXED
//! (map_size below; MDB_MAP_FULL recovery runbook: stop brfsd,
//! `mdb_copy -c csdb csdb.compact`, swap, start); the env lives under
//! state_dir/csdb and shares the free-space precondition with quarantine
//! (gap #18); LMDB keys cap at 511 bytes (4K pages) so relative paths are
//! limited to max_path_len — a digest-key scheme is Phase 3 material if
//! real trees ever need deeper.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("lmdb.h");
});

pub const State = enum(u8) {
    live = 1,
    deleted = 2,
};

pub const Id = struct {
    fsid: u64 = 0,
    fileid: u64 = 0,
    gen: u64 = 0,
};

/// ver = (origin_node, origin_seq).  origin is fnv1a64(node_id); seq is a
/// persistent per-origin strictly monotonic counter.  No wall clock anywhere
/// in ordering (T18).
pub const Version = struct {
    origin: u64 = 0,
    seq: u64 = 0,

    pub fn eql(a: Version, b: Version) bool {
        return a.origin == b.origin and a.seq == b.seq;
    }
};

/// How an incoming version relates to the stored one.
pub const Relation = enum {
    same, // identical: idempotent no-op
    newer, // same origin, higher seq: normal update
    older, // same origin, lower seq: stale, drop
    conflict_incoming_wins, // different origins; incoming has higher (seq, origin)
    conflict_stored_wins, // different origins; stored has higher (seq, origin)
};

pub fn relate(incoming: Version, stored: Version) Relation {
    if (incoming.eql(stored)) return .same;
    if (incoming.origin == stored.origin)
        return if (incoming.seq > stored.seq) .newer else .older;
    // Divergent origins: deterministic LWW on (seq, origin).
    const iw = incoming.seq > stored.seq or
        (incoming.seq == stored.seq and incoming.origin > stored.origin);
    return if (iw) .conflict_incoming_wins else .conflict_stored_wins;
}

pub const Record = struct {
    id: Id = .{},
    ver: Version = .{},
    size: u64 = 0,
    mtime_sec: i64 = 0,
    mtime_nsec: u32 = 0,
    mode: u16 = 0,
    is_dir: bool = false,
    state: State = .live,
    sha256: [32]u8 = [_]u8{0} ** 32,
    /// Wall-clock seconds when the tombstone was first applied (retention
    /// bookkeeping for gap #7 GC; never consulted for ordering and never
    /// sent on the wire).
    deleted_at: i64 = 0,
};

const DirKey = struct { fsid: u64, fileid: u64 };

const IdEnt = struct {
    path: []u8, // owned
    gen: u64,
};

/// LMDB keys cap at 511 bytes (4K pages); keep margin.  Longer relative
/// paths are rejected (error.NameTooLong) and surface in the daemon log.
pub const max_path_len = 480;

/// Gap #7 retention window (DFSR ConflictAndDeleted analog).
pub const tombstone_ttl_sec: i64 = 7 * 24 * 3600;

/// Fixed map size (sparse file; VA reservation, not physical).  See the
/// MDB_MAP_FULL runbook note in the module docs.
const map_size: usize = 1 << 30;

const db_dir = "csdb";
const dbi_records_name = "records";
const dbi_meta_name = "meta";
const meta_local_next_seq = "local_next_seq";
const meta_ring_seq = "ring_seq";
const meta_root_fsid = "root_fsid";
/// Seq reservation window: how far flush()/reserveSeqs() keep the
/// persisted ceiling ahead of the next issuable seq.  Bursts larger than
/// this between commits take the forced-reserve path in nextVersion().
const seq_reserve_window: u64 = 65536;

/// Record value layout: fixed 104 bytes, big-endian.  The path is the LMDB
/// key and is not repeated in the value.
const value_len = 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 2 + 1 + 1 + 8 + 32;

pub fn nodeOrigin(node_id: []const u8) u64 {
    return std.hash.Fnv1a_64.hash(node_id);
}

const LmdbError = error{
    NotFound,
    MapFull,
    NameTooLong,
    Corrupt,
    LmdbFail,
};

fn mdbCheck(rc: c_int) LmdbError!void {
    switch (rc) {
        0 => return,
        c.MDB_NOTFOUND => return error.NotFound,
        c.MDB_MAP_FULL => return error.MapFull,
        c.MDB_BAD_VALSIZE => return error.NameTooLong,
        c.MDB_CORRUPTED, c.MDB_PANIC, c.MDB_VERSION_MISMATCH => return error.Corrupt,
        else => return error.LmdbFail,
    }
}

fn mval(bytes: []const u8) c.MDB_val {
    return .{ .mv_size = bytes.len, .mv_data = @constCast(bytes.ptr) };
}

fn mvalSlice(v: *const c.MDB_val) []const u8 {
    const p: [*]const u8 = @ptrCast(v.mv_data);
    return p[0..v.mv_size];
}

/// All-member-ack horizon (gap #7): supplied by the daemon, which tracks
/// each member's announced version vector (from RESYNC_REQs).
pub const AckHorizon = struct {
    ctx: *const anyopaque,
    /// True when every configured member's vector covers ver.
    covers: *const fn (ctx: *const anyopaque, ver: Version) bool,
};

pub const ContentSet = struct {
    alloc: Allocator,
    state_dir: []const u8,
    map: std.StringHashMap(Record),
    /// (fsid, fileid) -> path for EVERY known vnode, dirs and files.
    /// Named events resolve parent/name; NAMELESS self events (MODIFY/
    /// ATTRIB carry no cnp — the kmod resolves no paths by design) resolve
    /// the subject directly through this index.  Entries come from records
    /// (upsert) and from the events themselves (learnId).
    id_index: std.AutoHashMap(DirKey, IdEnt),
    env: ?*c.MDB_env,
    dbi_records: c.MDB_dbi,
    dbi_meta: c.MDB_dbi,
    /// Pending write txn, begun lazily by the first mutation after the
    /// last commit; flush()/checkpoint() commit it (one atomic batch).
    wtxn: ?*c.MDB_txn = null,
    local_origin: u64,
    local_next_seq: u64 = 1,
    /// Reserved high-water for local version seqs, persisted in the meta
    /// DBI.  INVARIANT: every issued (local_origin, seq) satisfies
    /// seq < local_seq_ceiling AS PERSISTED, so a crash between flushes
    /// can never restart the counter behind an already-announced version
    /// (rig-proven 2026-08-25: kill -9 after a 4000-announce burst
    /// restarted at seq 1; the version reuse poisoned LWW mesh-wide —
    /// peers dropped the re-announces as duplicates of unrelated
    /// records, and phantom re-origins won the compare).
    local_seq_ceiling: u64 = 1,
    ring_seq: u64 = 0,
    /// Gap #16: the watched root's fsid, stamped on first-ever start.  On
    /// later opens a mismatch means the fs was force-unmounted (the path
    /// now resolves on the parent fs) or legitimately rebuilt — the daemon
    /// freezes scans/local announces rather than tombstoning a "vanished"
    /// tree mesh-wide.  0 = legacy db, stamp on next start.
    root_fsid: u64 = 0,
    needs_scan: bool = false,

    /// Open (creating if needed) state_dir/csdb and load every record.
    /// node_id derives the local origin for version stamping.  A corrupt
    /// env is moved aside and rebuilt empty with needs_scan set (the
    /// startup scan / RESYNC pull is the universal floor).
    pub fn open(alloc: Allocator, state_dir: []const u8, node_id: []const u8) !ContentSet {
        try std.fs.cwd().makePath(state_dir);

        var self = ContentSet{
            .alloc = alloc,
            .state_dir = try alloc.dupe(u8, state_dir),
            .map = std.StringHashMap(Record).init(alloc),
            .id_index = std.AutoHashMap(DirKey, IdEnt).init(alloc),
            .env = null,
            .dbi_records = 0,
            .dbi_meta = 0,
            .local_origin = nodeOrigin(node_id),
        };
        errdefer {
            self.closeEnv();
            self.deinitMaps();
            alloc.free(self.state_dir);
        }

        self.openEnv() catch {
            self.resetEnvAside();
            self.openEnv() catch return error.EnvOpen;
            self.needs_scan = true;
        };
        self.loadAll() catch {
            self.resetEnvAside();
            self.deinitMaps();
            self.map = std.StringHashMap(Record).init(alloc);
            self.id_index = std.AutoHashMap(DirKey, IdEnt).init(alloc);
            self.local_next_seq = 1;
            self.ring_seq = 0;
            self.openEnv() catch return error.EnvOpen;
            self.needs_scan = true;
        };

        // First-ever start (nothing persisted) has no ground truth at all:
        // the startup scan builds it.
        if (self.map.count() == 0 and self.local_next_seq == 1 and self.ring_seq == 0)
            self.needs_scan = true;

        // Reserve the first seq window before returning: from here on the
        // persisted ceiling is always strictly ahead of any issued seq.
        self.reserveSeqs() catch return error.EnvOpen;

        return self;
    }

    pub fn close(self: *ContentSet) void {
        self.flush() catch {}; // commit any pending batch
        self.closeEnv();
        self.deinitMaps();
        self.alloc.free(self.state_dir);
    }

    /// Crash simulation (kill -9 semantics): discard the pending batch
    /// exactly as a real crash would.  Tests only.
    pub fn abortAndClose(self: *ContentSet) void {
        self.abortTxn();
        self.closeEnv();
        self.deinitMaps();
        self.alloc.free(self.state_dir);
    }

    fn closeEnv(self: *ContentSet) void {
        if (self.env) |env| {
            _ = c.mdb_env_sync(env, 1); // orderly close: force the deferred meta flush
            c.mdb_dbi_close(env, self.dbi_records);
            c.mdb_dbi_close(env, self.dbi_meta);
            c.mdb_env_close(env);
            self.env = null;
        }
    }

    /// Move a suspect env aside so a fresh one can be built; the startup
    /// scan / RESYNC pull then rebuilds state from ground truth.
    fn resetEnvAside(self: *ContentSet) void {
        self.closeEnv();
        const dir = std.fs.path.join(self.alloc, &.{ self.state_dir, db_dir }) catch return;
        defer self.alloc.free(dir);
        const aside = std.fmt.allocPrint(self.alloc, "{s}.corrupt-{d}", .{ dir, std.time.timestamp() }) catch return;
        defer self.alloc.free(aside);
        std.fs.cwd().rename(dir, aside) catch {};
    }

    fn deinitMaps(self: *ContentSet) void {
        var it = self.map.iterator();
        while (it.next()) |e|
            self.alloc.free(e.key_ptr.*);
        self.map.deinit();
        var iit = self.id_index.iterator();
        while (iit.next()) |e|
            self.alloc.free(e.value_ptr.path);
        self.id_index.deinit();
    }

    fn openEnv(self: *ContentSet) !void {
        const dir = try std.fs.path.join(self.alloc, &.{ self.state_dir, db_dir });
        defer self.alloc.free(dir);
        try std.fs.cwd().makePath(dir);
        const dir_z = try self.alloc.dupeZ(u8, dir);
        defer self.alloc.free(dir_z);

        // MDB_NOTLS: the caller (daemon core thread, test runner) owns txn
        // discipline explicitly instead of LMDB tying txns to threads.
        // MDB_NOMETASYNC: one flush per commit instead of two — the second
        // (meta) fdatasync doubles ZFS TXG waits on the daemon's core loop
        // (rig-measured: doubled the post-big-file-install stall vs the POC
        // log backend).  Integrity is preserved across an OS crash (data
        // pages sync before the meta write); at most the LAST commit rolls
        // back, which idempotent replay + the scan floor heal — the set is
        // a cache of ground truth, never the only copy.
        try mdbCheck(c.mdb_env_create(&self.env));
        errdefer {
            c.mdb_env_close(self.env);
            self.env = null;
        }
        try mdbCheck(c.mdb_env_set_maxdbs(self.env, 4));
        try mdbCheck(c.mdb_env_set_mapsize(self.env, map_size));
        try mdbCheck(c.mdb_env_open(self.env, dir_z, c.MDB_NOTLS | c.MDB_NOMETASYNC, 0o600));

        var txn: ?*c.MDB_txn = null;
        try mdbCheck(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        try mdbCheck(c.mdb_dbi_open(txn, dbi_records_name, c.MDB_CREATE, &self.dbi_records));
        try mdbCheck(c.mdb_dbi_open(txn, dbi_meta_name, c.MDB_CREATE, &self.dbi_meta));
        try mdbCheck(c.mdb_txn_commit(txn));
    }

    fn loadAll(self: *ContentSet) !void {
        var txn: ?*c.MDB_txn = null;
        try mdbCheck(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
        defer c.mdb_txn_abort(txn);

        // The persisted value is the reserved CEILING (never itself
        // issued): resume allocation there, skipping the window's unused
        // tail — gaps in the seq stream are harmless (the version vector
        // is a per-origin max and resync is record-driven).
        if (self.getMeta(txn, meta_local_next_seq)) |v| {
            self.local_seq_ceiling = v;
            self.local_next_seq = v;
        }
        if (self.getMeta(txn, meta_ring_seq)) |v| self.ring_seq = v;
        if (self.getMeta(txn, meta_root_fsid)) |v| self.root_fsid = v;

        var cur: ?*c.MDB_cursor = null;
        try mdbCheck(c.mdb_cursor_open(txn, self.dbi_records, &cur));
        defer c.mdb_cursor_close(cur);

        var k: c.MDB_val = undefined;
        var v: c.MDB_val = undefined;
        while (true) {
            const rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_NEXT);
            if (rc == c.MDB_NOTFOUND) break;
            try mdbCheck(rc);
            const path = mvalSlice(&k);
            if (!validRelPath(path) or path.len > max_path_len) return error.Corrupt;
            const rec = try decodeRecord(mvalSlice(&v));
            const gop = try self.map.getOrPut(path);
            if (!gop.found_existing) {
                gop.key_ptr.* = try self.alloc.dupe(u8, path);
            } else {
                self.unindexDir(gop.value_ptr.*);
            }
            gop.value_ptr.* = rec;
            self.indexDir(gop.key_ptr.*, rec);
            // The local seq counter survives even if the record carrying
            // the max local seq is later GC'd (meta is the floor, the
            // record scan covers anything newer than the last commit).
            if (rec.ver.origin == self.local_origin and rec.ver.seq >= self.local_next_seq)
                self.local_next_seq = rec.ver.seq + 1;
        }
    }

    fn getMeta(self: *ContentSet, txn: ?*c.MDB_txn, key: []const u8) ?u64 {
        var k = mval(key);
        var v: c.MDB_val = undefined;
        if (c.mdb_get(txn, self.dbi_meta, &k, &v) != 0) return null;
        if (v.mv_size != 8) return null;
        const p: [*]const u8 = @ptrCast(v.mv_data);
        return std.mem.readInt(u64, p[0..8], .big);
    }

    pub fn lookup(self: *const ContentSet, path: []const u8) ?*const Record {
        return self.map.getPtr(path);
    }

    /// Resolve (fsid, fileid) -> path.  gen 0 on either side means "no
    /// opinion"; a nonzero mismatch means inode reuse — treat as unknown
    /// (scan floor).  Unknown -> null; the caller triggers a rescan.
    pub fn idPath(self: *const ContentSet, fsid: u64, fileid: u64, gen: u64) ?[]const u8 {
        const e = self.id_index.get(.{ .fsid = fsid, .fileid = fileid }) orelse return null;
        if (gen != 0 and e.gen != 0 and gen != e.gen) return null;
        return e.path;
    }

    /// Learn a (fsid, fileid) -> path mapping from a kernel event (the
    /// subject of a named event carries its fileid+gen).
    pub fn learnId(self: *ContentSet, fsid: u64, fileid: u64, gen: u64, path: []const u8) !void {
        if (fileid == 0) return;
        const key = DirKey{ .fsid = fsid, .fileid = fileid };
        const gop = try self.id_index.getOrPut(key);
        if (gop.found_existing) {
            if (std.mem.eql(u8, gop.value_ptr.path, path)) {
                if (gen != 0) gop.value_ptr.gen = gen;
                return;
            }
            self.alloc.free(gop.value_ptr.path);
        }
        gop.value_ptr.* = .{ .path = try self.alloc.dupe(u8, path), .gen = gen };
    }

    /// Forget a mapping (subject deleted).
    pub fn dropId(self: *ContentSet, fsid: u64, fileid: u64) void {
        if (fileid == 0) return;
        if (self.id_index.fetchRemove(.{ .fsid = fsid, .fileid = fileid })) |kv|
            self.alloc.free(kv.value.path);
    }

    /// Resolve a kernel event's (fsid, dir_fileid) to a directory path.
    /// Unknown (dir created while we were down and never scanned) -> null;
    /// the caller treats that as a scan trigger.
    pub fn dirPath(self: *const ContentSet, fsid: u64, fileid: u64) ?[]const u8 {
        return self.idPath(fsid, fileid, 0);
    }

    /// Register the replicated root itself in the id index (it has no
    /// record — relative paths never include it).  Its index path is "":
    /// events land directly under the root.
    pub fn indexRoot(self: *ContentSet, fsid: u64, fileid: u64) !void {
        try self.learnId(fsid, fileid, 0, "");
    }

    /// Persist a reserved ceiling seq_reserve_window ahead of the next
    /// issuable seq.  Called at open (first window) and by nextVersion
    /// when a burst exhausts the window mid-flight; flush() tops it up
    /// opportunistically on every commit.
    fn reserveSeqs(self: *ContentSet) !void {
        try self.ensureTxn();
        self.local_seq_ceiling = self.local_next_seq + seq_reserve_window;
        try self.flush();
    }

    /// Allocate the next local version.  The counter persists via the meta
    /// DBI at every commit — as a RESERVED CEILING, so a crash mid-burst
    /// resumes strictly ahead of every announced seq (never reuse).
    pub fn nextVersion(self: *ContentSet) Version {
        if (self.local_next_seq >= self.local_seq_ceiling) {
            // Window exhausted mid-burst (more than seq_reserve_window
            // versions issued since the last commit): commit the pending
            // batch and reserve the next window BEFORE issuing past the
            // persisted ceiling.
            self.reserveSeqs() catch {
                // Commit failed (flush marks needs_scan on failure): keep
                // the daemon live with an in-memory-only bump; the scan
                // floor rebuilds state and the next successful commit
                // re-establishes the invariant.
                self.local_seq_ceiling = self.local_next_seq + seq_reserve_window;
            };
        }
        const v = Version{ .origin = self.local_origin, .seq = self.local_next_seq };
        self.local_next_seq += 1;
        return v;
    }

    /// Insert or replace the record for path, write-through into the
    /// pending LMDB txn.  Caller flushes at batch boundaries.
    pub fn upsert(self: *ContentSet, path: []const u8, rec: Record) !void {
        if (!validRelPath(path)) return error.BadPath;
        if (path.len > max_path_len) return error.NameTooLong;

        var r = rec;
        // First tombstone application starts the retention clock; restarts
        // and re-upserts keep the original stamp.
        if (r.state == .deleted and r.deleted_at == 0)
            r.deleted_at = std.time.timestamp();
        // Keep the local seq floor monotonic even for records applied from
        // the wire with our own origin (restart replay corner).
        if (r.ver.origin == self.local_origin and r.ver.seq >= self.local_next_seq)
            self.local_next_seq = r.ver.seq + 1;

        var buf: [value_len]u8 = undefined;
        const body = encodeRecord(&buf, r);
        self.ensureTxn() catch |e| {
            self.abortTxn();
            return e;
        };
        var k = mval(path);
        var d = mval(body);
        mdbCheck(c.mdb_put(self.wtxn, self.dbi_records, &k, &d, 0)) catch |e| {
            self.abortTxn();
            return e;
        };

        const gop = try self.map.getOrPut(path);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.alloc.dupe(u8, path);
        } else {
            self.unindexDir(gop.value_ptr.*);
        }
        gop.value_ptr.* = r;
        self.indexDir(gop.key_ptr.*, r);
    }

    fn indexDir(self: *ContentSet, path: []const u8, rec: Record) void {
        if (rec.state != .live or rec.id.fileid == 0) return;
        self.learnId(rec.id.fsid, rec.id.fileid, rec.id.gen, path) catch {};
    }

    fn unindexDir(self: *ContentSet, rec: Record) void {
        if (rec.id.fileid == 0) return;
        self.dropId(rec.id.fsid, rec.id.fileid);
    }

    /// Gap #16: stamp the watched root's fsid (first-ever start).  Read
    /// side: root_fsid loaded by open(); a mismatch against the live fsid
    /// freezes the daemon's scans (forced-unmount protection).
    pub fn setRootFsid(self: *ContentSet, fsid: u64) !void {
        self.root_fsid = fsid;
        try self.ensureTxn();
        try self.flush();
    }

    /// Persist the current ring consumption point (USN analog).  Cheap;
    /// the daemon calls it on a timer and at shutdown.  Replays after a
    /// crash are safe because every downstream op is idempotent.
    pub fn checkpoint(self: *ContentSet, ring_seq: u64) !void {
        if (ring_seq == self.ring_seq) return;
        self.ring_seq = ring_seq;
        try self.ensureTxn();
        try self.flush();
    }

    /// Commit the pending write txn (records + ring-seq + local seq
    /// ceiling in ONE atomic fsync'd commit — gap #12).
    pub fn flush(self: *ContentSet) !void {
        if (self.wtxn == null) return;
        // Top up the reserved ceiling so the window stays a full
        // seq_reserve_window ahead at every commit boundary.
        if (self.local_next_seq + seq_reserve_window > self.local_seq_ceiling)
            self.local_seq_ceiling = self.local_next_seq + seq_reserve_window;
        self.putMeta(meta_local_next_seq, self.local_seq_ceiling) catch |e| {
            self.abortTxn();
            return e;
        };
        self.putMeta(meta_ring_seq, self.ring_seq) catch |e| {
            self.abortTxn();
            return e;
        };
        self.putMeta(meta_root_fsid, self.root_fsid) catch |e| {
            self.abortTxn();
            return e;
        };
        const txn = self.wtxn.?;
        self.wtxn = null; // commit consumes the handle either way
        mdbCheck(c.mdb_txn_commit(txn)) catch |e| {
            // The batch is lost but the in-memory map carries it: without a
            // rebuild the two diverge silently.  Force the scan floor.
            self.needs_scan = true;
            return e;
        };
    }

    /// LMDB's commit IS the snapshot — kept for API/behaviour parity with
    /// the POC backend (callers, tests).  Freelist re-compaction is an
    /// offline op (runbook: stop brfsd; `mdb_copy -c csdb csdb.compact`;
    /// swap; start).
    pub fn snapshot(self: *ContentSet) !void {
        try self.flush();
    }

    /// Gap #7: drop tombstones past the retention rule.  Live records are
    /// never collected.  A tombstone is collectable when EITHER the 7-day
    /// TTL expired (the DFSR ConflictAndDeleted window — the fallback for
    /// members gone too long) OR the all-member-ack horizon reports every
    /// configured member's version vector covers it (they have all SEEN
    /// the delete — early collection).  Returns the number collected.
    pub fn gcTombstones(self: *ContentSet, now_sec: i64, horizon: ?AckHorizon) !u64 {
        var doomed: std.ArrayList([]const u8) = .empty;
        defer doomed.deinit(self.alloc);
        var it = self.map.iterator();
        while (it.next()) |e| {
            const r = e.value_ptr;
            if (r.state != .deleted or r.deleted_at == 0) continue;
            const ttl_expired = now_sec - r.deleted_at >= tombstone_ttl_sec;
            const acked = if (horizon) |h| h.covers(h.ctx, r.ver) else false;
            if (!ttl_expired and !acked) continue;
            doomed.append(self.alloc, e.key_ptr.*) catch break;
        }
        if (doomed.items.len == 0) return 0;

        try self.ensureTxn();
        var n: u64 = 0;
        for (doomed.items) |p| {
            var k = mval(p);
            const rc = c.mdb_del(self.wtxn, self.dbi_records, &k, null);
            if (rc == c.MDB_NOTFOUND) {
                n += self.removeFromMap(p);
                continue;
            }
            mdbCheck(rc) catch |e| {
                self.abortTxn();
                return e;
            };
            n += self.removeFromMap(p);
        }
        try self.flush();
        return n;
    }

    /// Live records strictly under a dir path — the mass-delete guard's
    /// blast-radius weight for dir tombstones (a dir tombstone cascades
    /// to the whole subtree on receivers).  O(n) map walk; dir deletes
    /// only.
    pub fn liveDescendants(self: *const ContentSet, path: []const u8) u64 {
        var n: u64 = 0;
        var it = self.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.state != .live) continue;
            const k = e.key_ptr.*;
            if (k.len > path.len and std.mem.startsWith(u8, k, path) and k[path.len] == '/') n += 1;
        }
        return n;
    }

    /// Live-record count (O(n) map walk — the mass-delete guard calls it
    /// only past its absolute floor, never per event).
    pub fn liveCount(self: *const ContentSet) u64 {
        var n: u64 = 0;
        var it = self.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.state == .live) n += 1;
        }
        return n;
    }

    fn removeFromMap(self: *ContentSet, path: []const u8) u64 {
        // Tombstones carry no live id-index entry (unindexed at upsert).
        if (self.map.fetchRemove(path)) |kv| {
            self.alloc.free(kv.key);
            return 1;
        }
        return 0;
    }

    fn ensureTxn(self: *ContentSet) !void {
        if (self.wtxn != null) return;
        try mdbCheck(c.mdb_txn_begin(self.env, null, 0, &self.wtxn));
    }

    fn abortTxn(self: *ContentSet) void {
        if (self.wtxn) |txn| {
            c.mdb_txn_abort(txn);
            self.wtxn = null;
        }
    }

    fn putMeta(self: *ContentSet, key: []const u8, v: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, v, .big);
        var k = mval(key);
        var d = mval(&buf);
        try mdbCheck(c.mdb_put(self.wtxn, self.dbi_meta, &k, &d, 0));
    }
};

/// Wire/disk path rule: relative, no empty components, no "." or ".."
/// components, no leading '/'.  Shared by the loader and the protocol's
/// incoming-path validation.
pub fn validRelPath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/') return false;
    if (path[path.len - 1] == '/') return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |comp| {
        if (comp.len == 0) return false;
        if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return false;
    }
    return true;
}

fn encodeRecord(buf: []u8, rec: Record) []const u8 {
    std.debug.assert(buf.len >= value_len);
    var w = Writer{ .buf = buf };
    w.u64v(rec.id.fsid);
    w.u64v(rec.id.fileid);
    w.u64v(rec.id.gen);
    w.u64v(rec.ver.origin);
    w.u64v(rec.ver.seq);
    w.u64v(rec.size);
    w.i64v(rec.mtime_sec);
    w.u32v(rec.mtime_nsec);
    w.u16v(rec.mode);
    w.u8v(if (rec.is_dir) 1 else 0);
    w.u8v(@intFromEnum(rec.state));
    w.i64v(rec.deleted_at);
    w.bytes(&rec.sha256);
    return w.done();
}

fn decodeRecord(buf: []const u8) !Record {
    if (buf.len != value_len) return error.BadFrame;
    var r = Reader{ .buf = buf };
    var rec = Record{};
    rec.id.fsid = r.u64v();
    rec.id.fileid = r.u64v();
    rec.id.gen = r.u64v();
    rec.ver.origin = r.u64v();
    rec.ver.seq = r.u64v();
    rec.size = r.u64v();
    rec.mtime_sec = r.i64v();
    rec.mtime_nsec = r.u32v();
    rec.mode = r.u16v();
    rec.is_dir = r.u8v() != 0;
    rec.state = std.meta.intToEnum(State, r.u8v()) catch return error.BadFrame;
    rec.deleted_at = r.i64v();
    r.bytesInto(&rec.sha256);
    return rec;
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn u8v(self: *Writer, v: u8) void {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn u16v(self: *Writer, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn u32v(self: *Writer, v: u32) void {
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], v, .big);
        self.pos += 4;
    }
    fn u64v(self: *Writer, v: u64) void {
        std.mem.writeInt(u64, self.buf[self.pos..][0..8], v, .big);
        self.pos += 8;
    }
    fn i64v(self: *Writer, v: i64) void {
        std.mem.writeInt(i64, self.buf[self.pos..][0..8], v, .big);
        self.pos += 8;
    }
    fn bytes(self: *Writer, b: []const u8) void {
        @memcpy(self.buf[self.pos..][0..b.len], b);
        self.pos += b.len;
    }
    fn done(self: *Writer) []const u8 {
        return self.buf[0..self.pos];
    }
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn u8v(self: *Reader) u8 {
        defer self.pos += 1;
        return self.buf[self.pos];
    }
    fn u16v(self: *Reader) u16 {
        defer self.pos += 2;
        return std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
    }
    fn u32v(self: *Reader) u32 {
        defer self.pos += 4;
        return std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
    }
    fn u64v(self: *Reader) u64 {
        defer self.pos += 8;
        return std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
    }
    fn i64v(self: *Reader) i64 {
        defer self.pos += 8;
        return std.mem.readInt(i64, self.buf[self.pos..][0..8], .big);
    }
    fn bytesInto(self: *Reader, out: []u8) void {
        @memcpy(out, self.buf[self.pos..][0..out.len]);
        self.pos += out.len;
    }
};

// ---- tests ----

fn tmpStateDir(alloc: Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    return tmp.dir.realpathAlloc(alloc, ".");
}

fn sampleRecord(seq: u64) Record {
    return .{
        .id = .{ .fsid = 111, .fileid = 222, .gen = 3 },
        .ver = .{ .origin = nodeOrigin("test-node"), .seq = seq },
        .size = 4096,
        .mtime_sec = 1_700_000_000,
        .mtime_nsec = 123,
        .mode = 0o644,
        .sha256 = blk: {
            var d: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("content", &d, .{});
            break :blk d;
        },
    };
}

test "version relation matrix" {
    const a1 = Version{ .origin = 1, .seq = 5 };
    const a2 = Version{ .origin = 1, .seq = 6 };
    const b5 = Version{ .origin = 2, .seq = 5 };
    const b7 = Version{ .origin = 2, .seq = 7 };

    try std.testing.expectEqual(Relation.same, relate(a1, a1));
    try std.testing.expectEqual(Relation.newer, relate(a2, a1));
    try std.testing.expectEqual(Relation.older, relate(a1, a2));
    // Conflicts: higher seq wins; tie on seq -> higher origin wins.
    try std.testing.expectEqual(Relation.conflict_incoming_wins, relate(b7, a2));
    try std.testing.expectEqual(Relation.conflict_stored_wins, relate(a2, b7));
    try std.testing.expectEqual(Relation.conflict_incoming_wins, relate(b5, a1));
    try std.testing.expectEqual(Relation.conflict_stored_wins, relate(a1, b5));
}

test "upsert, lookup, tombstone, dir index" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();

    var drec = sampleRecord(1);
    drec.is_dir = true;
    drec.id = .{ .fsid = 55, .fileid = 66, .gen = 1 };
    try cs.upsert("sub", drec);
    try cs.upsert("sub/file.txt", sampleRecord(2));

    try std.testing.expect(cs.lookup("sub/file.txt") != null);
    try std.testing.expectEqualStrings("sub", cs.dirPath(55, 66).?);

    // Tombstone the dir: first-class deleted record, index entry removed.
    drec.state = .deleted;
    drec.ver = cs.nextVersion();
    try cs.upsert("sub", drec);
    try std.testing.expectEqual(State.deleted, cs.lookup("sub").?.state);
    try std.testing.expect(cs.dirPath(55, 66) == null);

    try std.testing.expectError(error.BadPath, cs.upsert("../escape", sampleRecord(3)));
    try std.testing.expectError(error.BadPath, cs.upsert("/abs", sampleRecord(3)));
    try std.testing.expectError(error.BadPath, cs.upsert("a//b", sampleRecord(3)));
}

test "persistence roundtrip incl. flush and seq recovery" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        try cs.upsert("a.txt", sampleRecord(1));
        var r2 = sampleRecord(2);
        r2.is_dir = true;
        r2.id = .{ .fsid = 7, .fileid = 8, .gen = 9 };
        try cs.upsert("d", r2);
        var r3 = sampleRecord(3);
        r3.state = .deleted;
        try cs.upsert("gone.txt", r3);
        try cs.checkpoint(4242);
        try cs.snapshot();
        cs.close();
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expect(!cs.needs_scan);
        try std.testing.expectEqual(@as(u64, 4242), cs.ring_seq);
        // Ceiling semantics: reopen resumes ahead of every issued seq
        // (the persisted value is a reserved ceiling, not the last next).
        try std.testing.expect(cs.local_next_seq >= 4);
        const rec = cs.lookup("a.txt").?;
        try std.testing.expectEqual(@as(u64, 4096), rec.size);
        try std.testing.expectEqual(@as(u16, 0o644), rec.mode);
        try std.testing.expectEqualStrings("d", cs.dirPath(7, 8).?);
        const gone = cs.lookup("gone.txt").?;
        try std.testing.expectEqual(State.deleted, gone.state);
        try std.testing.expect(gone.deleted_at > 0); // retention stamp persisted

        // Mutate, flush, reopen: committed batch survives.
        var r4 = sampleRecord(4);
        r4.size = 8192;
        try cs.upsert("a.txt", r4);
        try cs.flush();
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expectEqual(@as(u64, 8192), cs.lookup("a.txt").?.size);
        try std.testing.expect(cs.local_next_seq >= 5);
    }
}

test "kill -9 discards only the uncommitted batch (gap #12)" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        try cs.upsert("committed.txt", sampleRecord(1));
        try cs.flush(); // durable
        try cs.upsert("uncommitted.txt", sampleRecord(2)); // pending only
        cs.abortAndClose(); // crash: no commit, no orderly close
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expect(!cs.needs_scan); // a crash is normal wear
        try std.testing.expect(cs.lookup("committed.txt") != null);
        try std.testing.expect(cs.lookup("uncommitted.txt") == null);
        // The reserved ceiling committed with the first batch keeps the
        // counter ahead of the committed record's seq after the crash.
        try std.testing.expect(cs.local_next_seq >= 2);

        // The env is fully writable after crash recovery.
        try cs.upsert("after.txt", sampleRecord(3));
        try cs.flush();
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expect(cs.lookup("committed.txt") != null);
        try std.testing.expect(cs.lookup("after.txt") != null);
    }
}

test "kill -9 mid-burst never reuses an announced version seq" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    var issued: [3]u64 = undefined;
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        // Announces go out immediately; nothing commits before the crash.
        for (0..3) |i| issued[i] = cs.nextVersion().seq;
        cs.abortAndClose(); // kill -9: pending batch (incl. nothing) lost
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        // The reserved ceiling persisted at open: the reloaded counter is
        // strictly ahead of every seq the dead incarnation announced.
        for (issued) |s| try std.testing.expect(cs.local_next_seq > s);
        const v = cs.nextVersion();
        for (issued) |s| try std.testing.expect(v.seq != s);
    }
}

test "corrupt env is moved aside and rebuilt via scan floor" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    // Garbage where data.mdb should be: env open must fail and fall back.
    const csdb = try std.fs.path.join(alloc, &.{ dir, db_dir });
    defer alloc.free(csdb);
    try std.fs.cwd().makePath(csdb);
    const data_path = try std.fs.path.join(alloc, &.{ csdb, "data.mdb" });
    defer alloc.free(data_path);
    try std.fs.cwd().writeFile(.{ .sub_path = data_path, .data = &[_]u8{0xff} ** 4096 });

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();
    try std.testing.expect(cs.needs_scan);
    try cs.upsert("rebuilt.txt", sampleRecord(1));
    try cs.flush();
}

test "tombstone GC respects the retention TTL (gap #7)" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    const now = std.time.timestamp();
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        try cs.upsert("keep.txt", sampleRecord(1));
        var tomb = sampleRecord(50); // local origin, high seq: meta floor
        tomb.state = .deleted;
        try cs.upsert("gone.txt", tomb);
        try cs.flush();

        try std.testing.expectEqual(@as(u64, 0), try cs.gcTombstones(now, null)); // within TTL
        try std.testing.expect(cs.lookup("gone.txt") != null);
        try std.testing.expectEqual(@as(u64, 1), try cs.gcTombstones(now + tombstone_ttl_sec + 1, null));
        try std.testing.expect(cs.lookup("gone.txt") == null);
        try std.testing.expect(cs.lookup("keep.txt") != null); // live records never collected
        cs.close();
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expect(cs.lookup("gone.txt") == null); // GC is durable
        try std.testing.expect(cs.lookup("keep.txt") != null);
        // The local seq floor survived the GC of the record that carried it.
        try std.testing.expect(cs.local_next_seq >= 51);
    }
}

test "tombstone GC: all-member-ack horizon collects before TTL (gap #7)" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    const H = struct {
        cover: bool,
        fn covers(ctx: *const anyopaque, ver: Version) bool {
            _ = ver;
            const h: *const @This() = @ptrCast(@alignCast(ctx));
            return h.cover;
        }
    };
    var yes = H{ .cover = true };
    var no = H{ .cover = false };

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();
    var tomb = sampleRecord(7);
    tomb.state = .deleted;
    try cs.upsert("seen-by-all.txt", tomb);
    try cs.flush();

    const now = std.time.timestamp();
    // Horizon says no: retained within TTL.
    try std.testing.expectEqual(@as(u64, 0), try cs.gcTombstones(now, .{ .ctx = &no, .covers = H.covers }));
    try std.testing.expect(cs.lookup("seen-by-all.txt") != null);
    // Horizon says all members have seen it: collected immediately.
    try std.testing.expectEqual(@as(u64, 1), try cs.gcTombstones(now, .{ .ctx = &yes, .covers = H.covers }));
    try std.testing.expect(cs.lookup("seen-by-all.txt") == null);
}

test "gap #9 delete-vs-modify rule: LWW on (seq, origin) decides" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();

    // Tombstone N lands.
    var tomb = sampleRecord(5);
    tomb.state = .deleted;
    try cs.upsert("f.txt", tomb);

    // Offline modify M > N (same origin, higher seq) resurrects.
    var live = sampleRecord(6);
    live.state = .live;
    live.size = 12345;
    switch (relate(live.ver, cs.lookup("f.txt").?.ver)) {
        .newer, .conflict_incoming_wins => try cs.upsert("f.txt", live),
        else => return error.RuleBroken,
    }
    try std.testing.expectEqual(State.live, cs.lookup("f.txt").?.state);

    // A later tombstone beats the modify (delete wins; the daemon
    // quarantines the divergent copy — installer.quarantine).
    var tomb2 = sampleRecord(9);
    tomb2.state = .deleted;
    switch (relate(tomb2.ver, cs.lookup("f.txt").?.ver)) {
        .newer, .conflict_incoming_wins => try cs.upsert("f.txt", tomb2),
        else => return error.RuleBroken,
    }
    try std.testing.expectEqual(State.deleted, cs.lookup("f.txt").?.state);

    // A stale modify (M < N) must NOT resurrect.
    var stale = sampleRecord(4);
    stale.state = .live;
    switch (relate(stale.ver, cs.lookup("f.txt").?.ver)) {
        .same, .older, .conflict_stored_wins => {},
        else => return error.RuleBroken,
    }
    try std.testing.expectEqual(State.deleted, cs.lookup("f.txt").?.state);
}

test "empty first start requests a scan" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();
    try std.testing.expect(cs.needs_scan);
}

test "id index: learn, gen guard, drop" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();

    try cs.learnId(55, 100, 7, "sub/file.txt");
    try std.testing.expectEqualStrings("sub/file.txt", cs.idPath(55, 100, 7).?);
    try std.testing.expectEqualStrings("sub/file.txt", cs.idPath(55, 100, 0).?); // no opinion
    try std.testing.expect(cs.idPath(55, 100, 8) == null); // gen mismatch: inode reuse
    try std.testing.expect(cs.idPath(55, 999, 0) == null);

    // Rename remap: same fileid, new path.
    try cs.learnId(55, 100, 7, "sub/renamed.txt");
    try std.testing.expectEqualStrings("sub/renamed.txt", cs.idPath(55, 100, 7).?);

    cs.dropId(55, 100);
    try std.testing.expect(cs.idPath(55, 100, 0) == null);
}

test "validRelPath" {
    try std.testing.expect(validRelPath("a"));
    try std.testing.expect(validRelPath("a/b/c.txt"));
    try std.testing.expect(!validRelPath(""));
    try std.testing.expect(!validRelPath(".."));
    try std.testing.expect(!validRelPath(".."));
    try std.testing.expect(!validRelPath("a//b"));
    try std.testing.expect(!validRelPath("a/./b"));
    try std.testing.expect(!validRelPath("a/../b"));
    try std.testing.expect(!validRelPath(".."));
}
