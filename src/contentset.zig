//! contentset.zig — the BrFS content set: per-file current state.
//!
//! One record per path (relative to the replicated root): identity
//! (fsid/fileid/gen from the kernel feed), version (origin_node, origin_seq),
//! size, mtime, mode, sha256, and a first-class state flag
//! (live | deleted) — deletes are tombstones from day one; retention/GC
//! arrives with the LMDB swap in Phase 2 (decision locked 2026-08-24).
//!
//! POC persistence (per plan; LMDB in Phase 2): append-only log + periodic
//! snapshot under state_dir.  kill -9 mid-write safety (T8):
//!   - log records are framed [len u32][crc32 u32][payload]; a torn tail
//!     (short read or bad checksum) is detected on load and the file is
//!     truncated back to the last good record;
//!   - snapshots are written to a tmp file, fsynced, then rename(2)d into
//!     place; the log is only truncated after the snapshot is durable.
//! Corruption beyond a torn tail -> needs_scan: the caller falls back to a
//! full tree scan (the layered-durability floor — the set is a cache of
//! ground truth, never the only copy).
//!
//! A secondary dir index maps (fsid, fileid) -> directory path so kernel
//! events (which carry only dir_fileid + name, never paths) resolve to
//! wire-protocol paths.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

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
};

const DirKey = struct { fsid: u64, fileid: u64 };

const IdEnt = struct {
    path: []u8, // owned
    gen: u64,
};

const snap_name = "contentset.snap";
const snap_tmp_name = "contentset.snap.tmp";
const log_name = "contentset.log";

const snap_magic = "BRFSCS01";
const format_version: u32 = 1;

const rec_upsert: u8 = 1;
const rec_ring_seq: u8 = 2;

/// Fixed part of an upsert payload (everything before the path bytes).
const upsert_fixed_len = 1 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 2 + 1 + 1 + 32 + 2;

/// Safety bound while loading; the POC set is small and LMDB takes over in
/// Phase 2 before any real scale shows up.
const max_load_bytes = 256 * 1024 * 1024;

/// Snapshot cadence: whichever trips first.
const snap_max_log_bytes = 4 * 1024 * 1024;
const snap_max_ops = 4096;

pub fn nodeOrigin(node_id: []const u8) u64 {
    return std.hash.Fnv1a_64.hash(node_id);
}

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
    log_fd: posix.fd_t,
    local_origin: u64,
    local_next_seq: u64 = 1,
    ring_seq: u64 = 0,
    needs_scan: bool = false,
    log_bytes: u64 = 0,
    ops_since_snap: u64 = 0,

    /// Open (creating if needed) state_dir and load snapshot + log.
    /// node_id derives the local origin for version stamping.
    pub fn open(alloc: Allocator, state_dir: []const u8, node_id: []const u8) !ContentSet {
        try std.fs.cwd().makePath(state_dir);

        var self = ContentSet{
            .alloc = alloc,
            .state_dir = try alloc.dupe(u8, state_dir),
            .map = std.StringHashMap(Record).init(alloc),
            .id_index = std.AutoHashMap(DirKey, IdEnt).init(alloc),
            .log_fd = -1,
            .local_origin = nodeOrigin(node_id),
        };
        errdefer {
            self.deinitMaps();
            alloc.free(self.state_dir);
        }

        self.loadSnapshot();
        self.loadLog();

        // First-ever start (nothing persisted) has no ground truth at all:
        // the startup scan builds it.
        if (self.map.count() == 0 and self.local_next_seq == 1 and self.ring_seq == 0)
            self.needs_scan = true;

        const log_path = try std.fs.path.join(alloc, &.{ state_dir, log_name });
        defer alloc.free(log_path);
        const log_z = try alloc.dupeZ(u8, log_path);
        defer alloc.free(log_z);
        self.log_fd = try posix.open(log_z, .{ .ACCMODE = .RDWR, .CREAT = true, .APPEND = true }, 0o600);
        return self;
    }

    pub fn close(self: *ContentSet) void {
        if (self.log_fd >= 0) {
            posix.fsync(self.log_fd) catch {};
            posix.close(self.log_fd);
            self.log_fd = -1;
        }
        self.deinitMaps();
        self.alloc.free(self.state_dir);
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

    /// Allocate the next local version.  The counter persists via upsert
    /// records and snapshot headers; a state loss that resets it is healed
    /// by the scan fallback re-announcing with fresh (higher-origin-seq
    /// streams restart at the recomputed max + 1).
    pub fn nextVersion(self: *ContentSet) Version {
        const v = Version{ .origin = self.local_origin, .seq = self.local_next_seq };
        self.local_next_seq += 1;
        return v;
    }

    /// Insert or replace the record for path, appending to the log.
    /// Caller flushes at batch boundaries.
    pub fn upsert(self: *ContentSet, path: []const u8, rec: Record) !void {
        if (!validRelPath(path)) return error.BadPath;
        if (path.len > 1024) return error.NameTooLong;

        var buf: [upsert_fixed_len + 1024]u8 = undefined;
        const payload = try encodeUpsert(&buf, path, rec);
        try self.appendFrame(payload);

        const gop = try self.map.getOrPut(path);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.alloc.dupe(u8, path);
        } else {
            self.unindexDir(gop.key_ptr.*, gop.value_ptr.*);
        }
        gop.value_ptr.* = rec;
        self.indexDir(gop.key_ptr.*, rec);
        self.ops_since_snap += 1;
    }

    fn indexDir(self: *ContentSet, path: []const u8, rec: Record) void {
        if (rec.state != .live or rec.id.fileid == 0) return;
        self.learnId(rec.id.fsid, rec.id.fileid, rec.id.gen, path) catch {};
    }

    fn unindexDir(self: *ContentSet, path: []const u8, rec: Record) void {
        _ = path;
        if (rec.id.fileid == 0) return;
        self.dropId(rec.id.fsid, rec.id.fileid);
    }

    /// Persist the current ring consumption point (USN analog).  Cheap;
    /// the daemon calls it on a timer and at shutdown.  Replays after a
    /// crash are safe because every downstream op is idempotent.
    pub fn checkpoint(self: *ContentSet, ring_seq: u64) !void {
        if (ring_seq == self.ring_seq) return;
        var payload: [9]u8 = undefined;
        payload[0] = rec_ring_seq;
        std.mem.writeInt(u64, payload[1..9], ring_seq, .big);
        try self.appendFrame(&payload);
        self.ring_seq = ring_seq;
        try self.flush();
    }

    /// fsync the log; snapshot when the cadence trips.
    pub fn flush(self: *ContentSet) !void {
        try posix.fsync(self.log_fd);
        if (self.log_bytes >= snap_max_log_bytes or self.ops_since_snap >= snap_max_ops)
            try self.snapshot();
    }

    /// Write a full snapshot (tmp + fsync + rename), then truncate the log.
    pub fn snapshot(self: *ContentSet) !void {
        const alloc = self.alloc;
        const tmp_path = try std.fs.path.join(alloc, &.{ self.state_dir, snap_tmp_name });
        defer alloc.free(tmp_path);
        const final_path = try std.fs.path.join(alloc, &.{ self.state_dir, snap_name });
        defer alloc.free(final_path);

        const tmp_z = try alloc.dupeZ(u8, tmp_path);
        defer alloc.free(tmp_z);
        const fd = try posix.open(tmp_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        var ok = false;
        defer if (!ok) posix.close(fd);

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(alloc);

        try body.appendSlice(alloc, snap_magic);
        try appendInt(&body, alloc, u32, format_version);
        try appendInt(&body, alloc, u64, self.local_next_seq);
        try appendInt(&body, alloc, u64, self.ring_seq);
        try appendInt(&body, alloc, u64, self.map.count());

        var it = self.map.iterator();
        while (it.next()) |e| {
            var rbuf: [upsert_fixed_len + 4096]u8 = undefined;
            const payload = encodeUpsert(&rbuf, e.key_ptr.*, e.value_ptr.*) catch return error.NameTooLong;
            try appendInt(&body, alloc, u32, @intCast(payload.len));
            try appendInt(&body, alloc, u32, std.hash.Crc32.hash(payload));
            try body.appendSlice(alloc, payload);
        }
        try appendInt(&body, alloc, u32, std.hash.Crc32.hash(body.items));

        try writeAll(fd, body.items);
        try posix.fsync(fd);
        posix.close(fd);
        ok = true;

        const final_z = try alloc.dupeZ(u8, final_path);
        defer alloc.free(final_z);
        try posix.rename(tmp_z, final_z);
        fsyncDir(self.state_dir);

        // Snapshot is durable: start a fresh log.
        posix.close(self.log_fd);
        const log_path = try std.fs.path.join(alloc, &.{ self.state_dir, log_name });
        defer alloc.free(log_path);
        const log_z = try alloc.dupeZ(u8, log_path);
        defer alloc.free(log_z);
        self.log_fd = try posix.open(log_z, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true, .APPEND = true }, 0o600);
        self.log_bytes = 0;
        self.ops_since_snap = 0;
    }

    fn appendFrame(self: *ContentSet, payload: []const u8) !void {
        var hdr: [8]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(payload.len), .big);
        std.mem.writeInt(u32, hdr[4..8], std.hash.Crc32.hash(payload), .big);
        try writeAll(self.log_fd, &hdr);
        try writeAll(self.log_fd, payload);
        self.log_bytes += 8 + payload.len;
    }

    fn loadSnapshot(self: *ContentSet) void {
        const alloc = self.alloc;
        const path = std.fs.path.join(alloc, &.{ self.state_dir, snap_name }) catch return;
        defer alloc.free(path);
        const data = readWholeFile(alloc, path) orelse return;
        defer alloc.free(data);

        if (data.len < snap_magic.len + 4 + 8 + 8 + 8 + 4 + 4) {
            self.needs_scan = true;
            return;
        }
        const stored_crc = std.mem.readInt(u32, data[data.len - 4 ..][0..4], .big);
        const body = data[0 .. data.len - 4];
        if (std.hash.Crc32.hash(body) != stored_crc) {
            self.needs_scan = true;
            return;
        }
        if (!std.mem.eql(u8, body[0..8], snap_magic)) {
            self.needs_scan = true;
            return;
        }
        if (std.mem.readInt(u32, body[8..12], .big) != format_version) {
            self.needs_scan = true;
            return;
        }
        self.local_next_seq = std.mem.readInt(u64, body[12..20], .big);
        self.ring_seq = std.mem.readInt(u64, body[20..28], .big);
        // body[28..36] = record count (informational; the frames are truth)

        // Records are framed exactly like the log.  A bad frame here means
        // the file is corrupt despite the whole-file CRC (shouldn't happen);
        // treat as corruption.
        var pos: usize = 36;
        while (pos < body.len) {
            const parsed = parseFrame(body, &pos) orelse {
                self.needs_scan = true;
                return;
            };
            self.applyPayload(parsed) catch {
                self.needs_scan = true;
                return;
            };
        }
    }

    fn loadLog(self: *ContentSet) void {
        const alloc = self.alloc;
        const path = std.fs.path.join(alloc, &.{ self.state_dir, log_name }) catch return;
        defer alloc.free(path);
        const data = readWholeFile(alloc, path) orelse return;
        defer alloc.free(data);

        var pos: usize = 0;
        while (pos < data.len) {
            const frame_start = pos;
            const parsed = parseFrame(data, &pos) orelse {
                // Torn tail (kill -9 mid-write): truncate to the last good
                // record and carry on.  This is expected crash wear, not
                // corruption.
                truncateFile(path, frame_start);
                break;
            };
            self.applyPayload(parsed) catch {
                truncateFile(path, frame_start);
                self.needs_scan = true;
                break;
            };
            self.log_bytes = pos;
        }
    }

    fn applyPayload(self: *ContentSet, payload: []const u8) !void {
        switch (payload[0]) {
            rec_upsert => {
                const decoded = try decodeUpsert(payload);
                if (!validRelPath(decoded.path)) return error.BadPath;
                const gop = try self.map.getOrPut(decoded.path);
                if (!gop.found_existing) {
                    gop.key_ptr.* = try self.alloc.dupe(u8, decoded.path);
                } else {
                    self.unindexDir(gop.key_ptr.*, gop.value_ptr.*);
                }
                gop.value_ptr.* = decoded.rec;
                self.indexDir(gop.key_ptr.*, decoded.rec);
                if (decoded.rec.ver.origin == self.local_origin and
                    decoded.rec.ver.seq >= self.local_next_seq)
                    self.local_next_seq = decoded.rec.ver.seq + 1;
            },
            rec_ring_seq => {
                if (payload.len != 9) return error.BadFrame;
                const s = std.mem.readInt(u64, payload[1..9], .big);
                if (s > self.ring_seq) self.ring_seq = s;
            },
            else => return error.BadFrame,
        }
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

fn encodeUpsert(buf: []u8, path: []const u8, rec: Record) ![]const u8 {
    if (path.len > std.math.maxInt(u16)) return error.NameTooLong;
    if (buf.len < upsert_fixed_len + path.len) return error.NameTooLong;
    var w = Writer{ .buf = buf };
    w.u8v(rec_upsert);
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
    w.bytes(&rec.sha256);
    w.u16v(@intCast(path.len));
    w.bytes(path);
    return w.done();
}

const DecodedUpsert = struct { path: []const u8, rec: Record };

fn decodeUpsert(payload: []const u8) !DecodedUpsert {
    if (payload.len < upsert_fixed_len) return error.BadFrame;
    var r = Reader{ .buf = payload };
    if (r.u8v() != rec_upsert) return error.BadFrame;
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
    r.bytesInto(&rec.sha256);
    const plen = r.u16v();
    const path = r.rest();
    if (path.len != plen or plen == 0) return error.BadFrame;
    return .{ .path = path, .rec = rec };
}

/// Read one framed record from buf starting at *pos.  Advances *pos past
/// the frame on success; returns null on any short read or checksum
/// mismatch (caller decides torn-tail vs corruption).
fn parseFrame(buf: []const u8, pos: *usize) ?[]const u8 {
    if (buf.len - pos.* < 8) return null;
    const len = std.mem.readInt(u32, buf[pos.*..][0..4], .big);
    const crc = std.mem.readInt(u32, buf[pos.* + 4 ..][0..4], .big);
    if (len == 0 or len > max_load_bytes) return null;
    pos.* += 8;
    if (buf.len - pos.* < len) return null;
    const payload = buf[pos.* .. pos.* + len];
    if (std.hash.Crc32.hash(payload) != crc) return null;
    pos.* += len;
    return payload;
}

fn readWholeFile(alloc: Allocator, path: []const u8) ?[]u8 {
    const path_z = alloc.dupeZ(u8, path) catch return null;
    defer alloc.free(path_z);
    const fd = posix.open(path_z, .{ .ACCMODE = .RDONLY }, 0) catch return null;
    defer posix.close(fd);
    var st: posix.Stat = undefined;
    if (std.c.fstat(fd, &st) != 0) return null;
    if (st.size < 0 or st.size > max_load_bytes) return null;
    const size: usize = @intCast(st.size);
    const data = alloc.alloc(u8, size) catch return null;
    errdefer alloc.free(data);
    var off: usize = 0;
    while (off < size) {
        const n = posix.read(fd, data[off..]) catch {
            alloc.free(data);
            return null;
        };
        if (n == 0) break;
        off += n;
    }
    if (off != size) {
        alloc.free(data);
        return null;
    }
    return data;
}

extern "c" fn truncate(path: [*:0]const u8, length: c_long) c_int;

fn truncateFile(path: []const u8, len: usize) void {
    const path_z = std.posix.toPosixPath(path) catch return;
    _ = truncate(&path_z, @intCast(len));
}

fn fsyncDir(path: []const u8) void {
    const path_z = std.posix.toPosixPath(path) catch return;
    const fd = posix.open(std.mem.sliceTo(&path_z, 0), .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch return;
    defer posix.close(fd);
    posix.fsync(fd) catch {};
}

fn writeAll(fd: posix.fd_t, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        off += try posix.write(fd, data[off..]);
    }
}

fn appendInt(buf: *std.ArrayList(u8), alloc: Allocator, comptime T: type, v: T) !void {
    var tmp: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &tmp, v, .big);
    try buf.appendSlice(alloc, &tmp);
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
    fn rest(self: *Reader) []const u8 {
        defer self.pos = self.buf.len;
        return self.buf[self.pos..];
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

test "persistence roundtrip incl. snapshot and seq recovery" {
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
        try std.testing.expectEqual(@as(u64, 4), cs.local_next_seq);
        const rec = cs.lookup("a.txt").?;
        try std.testing.expectEqual(@as(u64, 4096), rec.size);
        try std.testing.expectEqual(@as(u16, 0o644), rec.mode);
        try std.testing.expectEqualStrings("d", cs.dirPath(7, 8).?);
        try std.testing.expectEqual(State.deleted, cs.lookup("gone.txt").?.state);

        // Mutate, flush (no snapshot), reopen: log replay path.
        var r4 = sampleRecord(4);
        r4.size = 8192;
        try cs.upsert("a.txt", r4);
        try cs.flush();
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expectEqual(@as(u64, 8192), cs.lookup("a.txt").?.size);
        try std.testing.expectEqual(@as(u64, 5), cs.local_next_seq);
    }
}

test "torn log tail (kill -9 mid-write) truncates cleanly" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        try cs.upsert("a.txt", sampleRecord(1));
        try cs.flush();
        cs.close();
    }

    // Simulate a torn write: garbage bytes appended after the good record.
    const log_path = try std.fs.path.join(alloc, &.{ dir, log_name });
    defer alloc.free(log_path);
    const log_z = try alloc.dupeZ(u8, log_path);
    defer alloc.free(log_z);
    const fd = try posix.open(log_z, .{ .ACCMODE = .WRONLY, .APPEND = true }, 0);
    try writeAll(fd, "\x00\x00\x00\x40partial");
    posix.close(fd);

    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expect(!cs.needs_scan); // torn tail is normal crash wear
        try std.testing.expect(cs.lookup("a.txt") != null);

        // Log must be writable after truncation repair.
        try cs.upsert("b.txt", sampleRecord(2));
        try cs.flush();
    }
    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        defer cs.close();
        try std.testing.expect(cs.lookup("a.txt") != null);
        try std.testing.expect(cs.lookup("b.txt") != null);
    }
}

test "corrupt snapshot falls back to scan flag" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmpStateDir(alloc, &tmp);
    defer alloc.free(dir);

    {
        var cs = try ContentSet.open(alloc, dir, "test-node");
        try cs.upsert("a.txt", sampleRecord(1));
        try cs.snapshot();
        cs.close();
    }
    const snap_path = try std.fs.path.join(alloc, &.{ dir, snap_name });
    defer alloc.free(snap_path);
    const snap_z = try alloc.dupeZ(u8, snap_path);
    defer alloc.free(snap_z);
    const fd = try posix.open(snap_z, .{ .ACCMODE = .WRONLY }, 0);
    _ = try posix.pwrite(fd, "\xff", 20); // inside the record area
    posix.close(fd);

    var cs = try ContentSet.open(alloc, dir, "test-node");
    defer cs.close();
    try std.testing.expect(cs.needs_scan);
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
    try std.testing.expect(!validRelPath("/a"));
    try std.testing.expect(!validRelPath("a/"));
    try std.testing.expect(!validRelPath("a//b"));
    try std.testing.expect(!validRelPath("a/./b"));
    try std.testing.expect(!validRelPath("a/../b"));
    try std.testing.expect(!validRelPath(".."));
}
