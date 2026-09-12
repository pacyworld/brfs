//! rdc.zig — RDC-style delta engine (D37): content-defined chunking and a
//! persistent, content-addressed local chunk index ("cross-file seeds").
//!
//! Files at or above daemon-configured `rdc_min` (default 64 KiB) replicate
//! by chunk manifest instead of whole-file transfer:
//!
//!   - Chunking is content-defined (gear rolling hash, FastCDC shape):
//!     cut when (fp & mask) == 0 on a rolling fingerprint, bounded to
//!     [min_chunk, max_chunk].  Insertions/deletions shift only nearby
//!     chunk boundaries, so an edit replicates as the chunks it touched.
//!     Chunk identity = BLAKE3 truncated to 16 bytes (seed membership is
//!     a hint verified by the FINAL whole-file SHA-256 of the assembled
//!     staging; a collision could only waste a transfer, and inside an
//!     authenticated mesh that is already far past unlikely).  BLAKE3,
//!     not SHA-256: Zig's portable sha2 runs ~24 MB/s on the rig Xeons
//!     (no SHA-NI) vs BLAKE3's ~330 MB/s — per-chunk hashing dominated
//!     the D37 worker pass 10:1 (rig-proven 2026-09-12: T13's 1.1 GB
//!     announce blew the test budget until the swap).
//!
//!   - The chunk index is a SEPARATE LMDB env (state_dir/rdcdb) — a
//!     rebuildable cache, never the only copy of anything.  Two DBIs:
//!       by_path: key  = path bytes | off u64 BE
//!                val  = hash16 | len u32 BE
//!       by_hash: DUPSORT key  = hash16
//!                val  = pathlen u16 BE | path | off u64 BE | len u32 BE
//!     by_path makes same-path eviction O(chunks of that file); by_hash
//!     answers "do I already hold these bytes ANYWHERE in my tree" —
//!     cross-file dedup falls out of content addressing (copies, renames
//!     with edits, partially-related artifacts).
//!
//!   - Correctness rests on VERIFY-ON-USE: a by_hash candidate is pread
//!     and hash-checked before its bytes are staged.  A stale entry (its
//!     file was modified/deleted after indexing) simply fails the check
//!     and degenerates to a literal fetch.  The index may be deleted
//!     wholesale with no correctness impact — replication falls back to
//!     full literal transfer, which is the pre-D37 behavior.
//!
//!   - All index I/O happens on the daemon core thread (MDB_NOTLS,
//!     matching contentset.csdb).  The env opens MDB_NOSYNC (a lost index
//!     commit is a lost delta opportunity, nothing more) with mdb_env_sync
//!     driven at the daemon's checkpoint cadence.
//!
//!   - MDB_MAP_FULL degrades the index to read-only misses: puts fail,
//!     the daemon latches a disabled flag (metric + log), transfers
//!     continue as literal pulls.  Operator recovery: stop brfsd, remove
//!     state_dir/rdcdb, start (rebuilds lazily as content is hashed).

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const contentset = @import("contentset.zig");

const c = @cImport({
    @cInclude("lmdb.h");
});

const evp = @cImport({
    @cInclude("openssl/evp.h");
});

/// Chunk content identity (truncated BLAKE3).
fn chunkHash(bytes: []const u8) [hash_len]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &d, .{});
    var h: [hash_len]u8 = undefined;
    @memcpy(&h, d[0..hash_len]);
    return h;
}

// ---- chunking (locked protocol constants; changine them is a fork) ----

pub const min_chunk: u32 = 16 * 1024;
pub const max_chunk: u32 = 64 * 1024;
/// Cut mask: geometric cut distribution with mean max(avg-min) after the
/// minimum run — single-region mask p = 2^-14 -> overall mean ~32 KiB.
const cut_mask: u64 = (1 << 14) - 1;

pub const hash_len = 16;

/// Deterministic gear table (SplitMix64 from a fixed seed at comptime):
/// every build on every node chunks identically.
const gear: [256]u64 = blk: {
    @setEvalBranchQuota(3000);
    var s: u64 = 0x6272_6673_5f72_6463; // "brfs_rdc"
    var tbl: [256]u64 = undefined;
    for (&tbl) |*e| {
        s +%= 0x9E3779B97F4A7C15;
        var z = s;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        z = z ^ (z >> 31);
        e.* = z;
    }
    break :blk tbl;
};

pub const ChunkEnt = struct {
    off: u64,
    len: u32,
    hash: [hash_len]u8,
};

/// Split data into content-defined chunks, appending {off, len, hash}
/// entries.  off base is `base_off` (0 for the whole file).
pub fn chunkSlice(alloc: Allocator, data: []const u8, base_off: u64, out: *std.ArrayList(ChunkEnt)) !void {
    var start: usize = 0;
    while (start < data.len) {
        const len = chunkFind(data, start);
        try out.append(alloc, .{
            .off = base_off + start,
            .len = @intCast(len),
            .hash = chunkHash(data[start .. start + len]),
        });
        start += len;
    }
}

/// Length of the chunk that starts at data[start..].
fn chunkFind(data: []const u8, start: usize) usize {
    const remaining = data.len - start;
    if (remaining <= min_chunk) return remaining;

    var fp: u64 = 0;
    var i: usize = start + min_chunk;
    const hard_end = start + @min(remaining, max_chunk);
    const g = &gear;
    const mask = cut_mask;
    while (i < hard_end) : (i += 1) {
        fp = (fp <<| 1) +% g[data[i]];
        if (fp & mask == 0) return i - start + 1;
    }
    return hard_end - start;
}

/// Chunk + whole-file hash in ONE read pass (the async local hash job's
/// big-file path: sha256 for the announce, chunk entries for the index).
/// The whole-file digest uses libcrypto EVP: Zig's portable sha2 is
/// ~10x slower than OpenSSL's AVX2 backend on the rig CPUs (no SHA-NI),
/// and big-file announce latency is user-visible.
pub const FileDigest = struct {
    sha256: [32]u8,
    size: u64,
    chunks: []ChunkEnt, // owned
};

const EvpCtx = struct {
    ctx: ?*evp.EVP_MD_CTX,

    fn init() !EvpCtx {
        const ctx = evp.EVP_MD_CTX_new() orelse return error.CryptoFail;
        if (evp.EVP_DigestInit_ex(ctx, evp.EVP_sha256(), null) != 1) {
            evp.EVP_MD_CTX_free(ctx);
            return error.CryptoFail;
        }
        return .{ .ctx = ctx };
    }
    fn update(self: *EvpCtx, bytes: []const u8) !void {
        if (evp.EVP_DigestUpdate(self.ctx, bytes.ptr, bytes.len) != 1)
            return error.CryptoFail;
    }
    fn final(self: *EvpCtx, out: *[32]u8) !void {
        var n: c_uint = 0;
        if (evp.EVP_DigestFinal_ex(self.ctx, out, &n) != 1 or n != 32)
            return error.CryptoFail;
    }
    fn deinit(self: *EvpCtx) void {
        evp.EVP_MD_CTX_free(self.ctx);
    }
};

pub fn hashAndChunkFile(alloc: Allocator, abs: []const u8) !FileDigest {
    const fd = try posix.open(abs, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(fd);
    var h = try EvpCtx.init();
    defer h.deinit();
    var chunks: std.ArrayList(ChunkEnt) = .empty;
    errdefer chunks.deinit(alloc);

    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(alloc);
    var size: u64 = 0;
    var buf: [256 * 1024]u8 = undefined;
    while (true) {
        const n = try posix.read(fd, &buf);
        if (n == 0) break;
        try h.update(buf[0..n]);
        // Chunks are cut only across COMPLETE data; keep a tail shorter
        // than max_chunk buffered until more data or EOF.
        try pending.appendSlice(alloc, buf[0..n]);
        size += n;
        var consumed: usize = 0;
        while (pending.items.len - consumed > max_chunk) {
            const l = chunkFind(pending.items, consumed);
            if (consumed + l >= pending.items.len) break; // cut needs confirmed tail
            try chunks.append(alloc, .{
                .off = size - pending.items.len + consumed,
                .len = @intCast(l),
                .hash = chunkHash(pending.items[consumed .. consumed + l]),
            });
            consumed += l;
        }
        if (consumed > 0) {
            std.mem.copyForwards(u8, pending.items[0 .. pending.items.len - consumed], pending.items[consumed..]);
            pending.shrinkRetainingCapacity(pending.items.len - consumed);
        }
    }
    // Flush the tail buffer (<= ~2*max_chunk): cut freely to EOF.
    try chunkSlice(alloc, pending.items, size - pending.items.len, &chunks);

    var sha: [32]u8 = undefined;
    try h.final(&sha);
    return .{ .sha256 = sha, .size = size, .chunks = try chunks.toOwnedSlice(alloc) };
}

/// Read fd's bytes at [off, off+len) and confirm they match the chunk
/// hash (verify-on-use for a by_hash candidate).  IO errors are misses.
pub fn verifyChunkAt(abs: []const u8, off: u64, len: u32, hash: *const [hash_len]u8) bool {
    const fd = posix.open(abs, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    defer posix.close(fd);
    var buf: [max_chunk]u8 = undefined;
    if (len > buf.len) return false;
    var got: usize = 0;
    while (got < len) {
        const n = posix.pread(fd, buf[got..len], @intCast(off + got)) catch return false;
        if (n == 0) return false;
        got += n;
    }
    const actual = chunkHash(buf[0..len]);
    return std.mem.eql(u8, &actual, hash);
}

/// Verify + return the chunk bytes (the completion worker's copy path —
/// it needs the bytes to pwrite into staging, not just the assurance).
/// null = hash mismatch (stale index entry); error = IO failure.
pub fn readChunkVerified(alloc: Allocator, abs: []const u8, off: u64, len: u32, hash: *const [hash_len]u8) !?[]u8 {
    if (len == 0 or len > max_chunk) return null;
    const fd = posix.open(abs, .{ .ACCMODE = .RDONLY }, 0) catch return null;
    defer posix.close(fd);
    const buf = try alloc.alloc(u8, len);
    errdefer alloc.free(buf);
    var got: usize = 0;
    while (got < len) {
        const n = posix.pread(fd, buf[got..], @intCast(off + got)) catch {
            alloc.free(buf);
            return null;
        };
        if (n == 0) {
            alloc.free(buf);
            return null;
        }
        got += n;
    }
    const actual = chunkHash(buf);
    if (!std.mem.eql(u8, &actual, hash)) {
        alloc.free(buf);
        return null;
    }
    return buf;
}

// ---- the chunk index (rdcdb) ----

const map_size: usize = 4 << 30; // sparse VA reservation
const dbi_by_path_name = "by_path";
const dbi_by_hash_name = "by_hash";
const db_dir = "rdcdb";

fn check(rc: c_int) !void {
    switch (rc) {
        0 => {},
        c.MDB_MAP_FULL => return error.MapFull,
        c.MDB_BAD_VALSIZE => return error.NameTooLong,
        c.MDB_CORRUPTED, c.MDB_PANIC, c.MDB_VERSION_MISMATCH => return error.Corrupt,
        else => return error.Lmdb,
    }
}

fn mval(bytes: []const u8) c.MDB_val {
    return .{ .mv_size = bytes.len, .mv_data = @constCast(bytes.ptr) };
}

/// One place the bytes of a chunk live locally.
pub const Cand = struct {
    path: []const u8, // borrowed from the cursor — copy before txn close
    off: u64,
    len: u32,
};

pub const Index = struct {
    env: ?*c.MDB_env,
    dbi_by_path: c.MDB_dbi,
    dbi_by_hash: c.MDB_dbi,

    /// Open (creating) state_dir/rdcdb.  A corrupt env is moved aside and
    /// rebuilt empty — the index is a cache.
    pub fn open(alloc: Allocator, state_dir: []const u8) !Index {
        const dir = try std.fs.path.join(alloc, &.{ state_dir, db_dir });
        defer alloc.free(dir);
        const env = try openEnvAt(dir);
        return env;
    }

    fn openEnvAt(dir: []const u8) !Index {
        try std.fs.cwd().makePath(dir);
        const dir_z_buf = try std.posix.toPosixPath(dir);
        const dir_z: [*:0]const u8 = &dir_z_buf;
        var idx = Index{
            .env = null,
            .dbi_by_path = 0,
            .dbi_by_hash = 0,
        };
        try check(c.mdb_env_create(&idx.env));
        errdefer c.mdb_env_close(idx.env);
        try check(c.mdb_env_set_maxdbs(idx.env, 4));
        try check(c.mdb_env_set_mapsize(idx.env, map_size));
        try check(c.mdb_env_open(idx.env, dir_z, c.MDB_NOTLS | c.MDB_NOSYNC, 0o600));
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(idx.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        try check(c.mdb_dbi_open(txn, dbi_by_path_name, c.MDB_CREATE, &idx.dbi_by_path));
        try check(c.mdb_dbi_open(txn, dbi_by_hash_name, c.MDB_CREATE | c.MDB_DUPSORT, &idx.dbi_by_hash));
        try check(c.mdb_txn_commit(txn));
        return idx;
    }

    /// Corruption recovery: move the env aside and rebuild empty.
    /// (csdb's pattern; callers retry open() after.)
    pub fn moveAside(alloc: Allocator, state_dir: []const u8) !void {
        const dir = try std.fs.path.join(alloc, &.{ state_dir, db_dir });
        defer alloc.free(dir);
        const aside = try std.fmt.allocPrint(alloc, "{s}.corrupt-{d}", .{ dir, std.time.timestamp() });
        defer alloc.free(aside);
        std.fs.cwd().rename(dir, aside) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
    }

    pub fn close(self: *Index) void {
        if (self.env) |env| {
            _ = c.mdb_env_sync(env, 1);
            c.mdb_env_close(env);
            self.env = null;
        }
    }

    /// NOSYNC env: force deferred pages out (daemon checkpoint cadence).
    pub fn sync(self: *Index) void {
        _ = c.mdb_env_sync(self.env, 1);
    }

    /// Replace path's chunk set with `chunks` (delete-before-insert keeps
    /// same-path replaces bounded).  One commit for the whole batch.
    pub fn addPath(self: *Index, path: []const u8, chunks: []const ChunkEnt) !void {
        if (path.len == 0 or path.len > contentset.max_path_len) return error.NameTooLong;
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        try self.removePathTxn(txn, path);
        var kbuf: [contentset.max_path_len + 8]u8 = undefined;
        @memcpy(kbuf[0..path.len], path);
        for (chunks) |ch| {
            std.mem.writeInt(u64, kbuf[path.len..][0..8], ch.off, .big);
            var vbuf: [hash_len + 4]u8 = undefined;
            @memcpy(vbuf[0..hash_len], &ch.hash);
            std.mem.writeInt(u32, vbuf[hash_len..][0..4], ch.len, .big);
            var k = mval(kbuf[0 .. path.len + 8]);
            var v = mval(&vbuf);
            try check(c.mdb_put(txn, self.dbi_by_path, &k, &v, 0));
            // by_hash dup: u16 pathlen | path | u64 off | u32 len
            var dbuf: [2 + contentset.max_path_len + 8 + 4]u8 = undefined;
            std.mem.writeInt(u16, dbuf[0..2], @intCast(path.len), .big);
            @memcpy(dbuf[2 .. 2 + path.len], path);
            std.mem.writeInt(u64, dbuf[2 + path.len ..][0..8], ch.off, .big);
            std.mem.writeInt(u32, dbuf[2 + path.len + 8 ..][0..4], ch.len, .big);
            var hk = mval(&ch.hash);
            var hv = mval(dbuf[0 .. 2 + path.len + 8 + 4]);
            try check(c.mdb_put(txn, self.dbi_by_hash, &hk, &hv, 0));
        }
        try check(c.mdb_txn_commit(txn));
    }

    /// Drop everything indexed for path (tombstone sweep / path eviction).
    pub fn removePath(self: *Index, path: []const u8) !void {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        try self.removePathTxn(txn, path);
        try check(c.mdb_txn_commit(txn));
    }

    fn removePathTxn(self: *Index, txn: ?*c.MDB_txn, path: []const u8) !void {
        // Walk by_path's prefix range for path; delete each row and its
        // by_hash dup.  Keys are path | u64 BE off, so the range is a
        // simple prefix scan.
        var cur: ?*c.MDB_cursor = null;
        try check(c.mdb_cursor_open(txn, self.dbi_by_path, &cur));
        defer c.mdb_cursor_close(cur);
        var kbuf: [contentset.max_path_len + 8]u8 = undefined;
        @memcpy(kbuf[0..path.len], path);
        @memset(kbuf[path.len..][0..8], 0);
        var k = mval(kbuf[0 .. path.len + 8]);
        var v: c.MDB_val = undefined;
        var rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_SET_RANGE);
        while (rc == 0) {
            const key = vptr(&k);
            if (key.len != path.len + 8 or !std.mem.eql(u8, key[0..path.len], path)) break;
            const val = vptr(&v);
            if (val.len == hash_len + 4) {
                // Remove the by_hash dup for this (hash, path, off, len).
                var dbuf: [2 + contentset.max_path_len + 8 + 4]u8 = undefined;
                std.mem.writeInt(u16, dbuf[0..2], @intCast(path.len), .big);
                @memcpy(dbuf[2 .. 2 + path.len], path);
                std.mem.writeInt(u64, dbuf[2 + path.len ..][0..8], std.mem.readInt(u64, key[path.len..][0..8], .big), .big);
                @memcpy(dbuf[2 + path.len + 8 ..][0..4], val[hash_len..][0..4]);
                var hk = mval(val[0..hash_len]);
                var hv = mval(dbuf[0 .. 2 + path.len + 8 + 4]);
                // NOTFOUND tolerable: by_hash is only a hint layer.
                _ = c.mdb_del(txn, self.dbi_by_hash, &hk, &hv);
            }
            try check(c.mdb_cursor_del(cur, 0));
            rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_NEXT);
        }
        if (rc != c.MDB_NOTFOUND) try check(rc);
    }

    fn vptr(mv: *const c.MDB_val) []const u8 {
        return @as([*]const u8, @ptrCast(mv.mv_data))[0..mv.mv_size];
    }

    /// Candidates holding chunk `hash` (up to cap).  Paths borrow the
    /// read txn's pages — the caller copies before dropping the txn.
    pub fn lookup(self: *Index, hash: *const [hash_len]u8, out: []Cand) !usize {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
        defer c.mdb_txn_abort(txn);
        var cur: ?*c.MDB_cursor = null;
        try check(c.mdb_cursor_open(txn, self.dbi_by_hash, &cur));
        defer c.mdb_cursor_close(cur);
        var k = mval(hash);
        var v: c.MDB_val = undefined;
        var rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_SET_KEY);
        var n: usize = 0;
        while (rc == 0 and n < out.len) : (rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_NEXT_DUP)) {
            const val = vptr(&v);
            if (val.len < 2 + 8 + 4) continue;
            const plen = std.mem.readInt(u16, val[0..2], .big);
            if (val.len != 2 + plen + 8 + 4) continue;
            out[n] = .{
                .path = val[2 .. 2 + plen],
                .off = std.mem.readInt(u64, val[2 + plen ..][0..8], .big),
                .len = std.mem.readInt(u32, val[2 + plen + 8 ..][0..4], .big),
            };
            n += 1;
        }
        if (rc != c.MDB_NOTFOUND and rc != 0) try check(rc);
        return n;
    }

    /// Re-key a file's indexed chunks from old_path to new_path (wire or
    /// local rename with proven-identical content — no re-read needed).
    pub fn renamePath(self: *Index, alloc: Allocator, old_path: []const u8, new_path: []const u8) !void {
        const chunks = try self.chunksOf(alloc, old_path);
        defer alloc.free(chunks);
        if (chunks.len == 0) return;
        try self.removePath(old_path);
        try self.addPath(new_path, chunks);
    }

    /// Re-key every indexed path under an old directory prefix (dir
    /// renames move indexed descendant files).
    pub fn renamePrefix(self: *Index, alloc: Allocator, old_prefix: []const u8, new_prefix: []const u8) !void {
        var victims: std.ArrayList([]u8) = .empty;
        defer {
            for (victims.items) |p| alloc.free(p);
            victims.deinit(alloc);
        }
        // Collect distinct paths whose key starts with old_prefix (+ '/').
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
        defer c.mdb_txn_abort(txn);
        var cur: ?*c.MDB_cursor = null;
        try check(c.mdb_cursor_open(txn, self.dbi_by_path, &cur));
        defer c.mdb_cursor_close(cur);
        var k: c.MDB_val = undefined;
        var v: c.MDB_val = undefined;
        var last: ?[]u8 = null;
        defer if (last) |l| alloc.free(l);
        var rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_FIRST);
        while (rc == 0) : (rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_NEXT)) {
            const key = vptr(&k);
            if (key.len < 8) continue;
            const path = key[0 .. key.len - 8];
            if (last) |l| {
                if (std.mem.eql(u8, l, path)) continue;
                alloc.free(l);
            }
            last = try alloc.dupe(u8, path);
            if (path.len > old_prefix.len and
                std.mem.startsWith(u8, path, old_prefix) and
                path[old_prefix.len] == '/')
                try victims.append(alloc, try alloc.dupe(u8, path));
        }
        if (rc != c.MDB_NOTFOUND) try check(rc);
        for (victims.items) |vp| {
            const rest = vp[old_prefix.len..];
            const np = try std.fmt.allocPrint(alloc, "{s}{s}", .{ new_prefix, rest });
            defer alloc.free(np);
            try self.renamePath(alloc, vp, np);
        }
    }

    /// Read back path's indexed entries (renamePath's source).
    fn chunksOf(self: *Index, alloc: Allocator, path: []const u8) ![]ChunkEnt {
        var out: std.ArrayList(ChunkEnt) = .empty;
        errdefer out.deinit(alloc);
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
        defer c.mdb_txn_abort(txn);
        var cur: ?*c.MDB_cursor = null;
        try check(c.mdb_cursor_open(txn, self.dbi_by_path, &cur));
        defer c.mdb_cursor_close(cur);
        var kbuf: [contentset.max_path_len + 8]u8 = undefined;
        @memcpy(kbuf[0..path.len], path);
        @memset(kbuf[path.len..][0..8], 0);
        var k = mval(kbuf[0 .. path.len + 8]);
        var v: c.MDB_val = undefined;
        var rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_SET_RANGE);
        while (rc == 0) : (rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_NEXT)) {
            const key = vptr(&k);
            if (key.len != path.len + 8 or !std.mem.eql(u8, key[0..path.len], path)) break;
            const val = vptr(&v);
            if (val.len != hash_len + 4) continue;
            var h: [hash_len]u8 = undefined;
            @memcpy(&h, val[0..hash_len]);
            try out.append(alloc, .{
                .off = std.mem.readInt(u64, key[path.len..][0..8], .big),
                .len = std.mem.readInt(u32, val[hash_len..][0..4], .big),
                .hash = h,
            });
        }
        if (rc != c.MDB_NOTFOUND) try check(rc);
        return out.toOwnedSlice(alloc);
    }

    /// Hourly sweep: remove indexed chunks for paths the callback says are
    /// no longer live in the content set.  Walks distinct paths (cursor
    /// prefix groups), one removal txn per dead path.
    pub fn sweep(self: *Index, alloc: Allocator, ctx: *const anyopaque, isLive: *const fn (ctx: *const anyopaque, path: []const u8) bool) !usize {
        var removed: usize = 0;
        var dead: std.ArrayList([]u8) = .empty;
        defer {
            for (dead.items) |p| alloc.free(p);
            dead.deinit(alloc);
        }
        {
            var txn: ?*c.MDB_txn = null;
            try check(c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn));
            defer c.mdb_txn_abort(txn);
            var cur: ?*c.MDB_cursor = null;
            try check(c.mdb_cursor_open(txn, self.dbi_by_path, &cur));
            defer c.mdb_cursor_close(cur);
            var k: c.MDB_val = undefined;
            var v: c.MDB_val = undefined;
            var last: ?[]u8 = null;
            defer if (last) |l| alloc.free(l);
            var rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_FIRST);
            while (rc == 0) : (rc = c.mdb_cursor_get(cur, &k, &v, c.MDB_NEXT)) {
                const key = vptr(&k);
                if (key.len < 8) continue;
                const path = key[0 .. key.len - 8];
                if (last) |l| {
                    if (std.mem.eql(u8, l, path)) continue;
                    alloc.free(l);
                }
                last = try alloc.dupe(u8, path);
                if (!isLive(ctx, path)) try dead.append(alloc, try alloc.dupe(u8, path));
            }
            if (rc != c.MDB_NOTFOUND) try check(rc);
        }
        for (dead.items) |p| {
            try self.removePath(p);
            removed += 1;
        }
        return removed;
    }

    /// Indexed chunk count (by_hash entry count — one per indexed chunk
    /// relation; equals by_path row count).
    pub fn chunkCount(self: *Index) u64 {
        var txn: ?*c.MDB_txn = null;
        if (c.mdb_txn_begin(self.env, null, c.MDB_RDONLY, &txn) != 0) return 0;
        defer c.mdb_txn_abort(txn);
        var st: c.MDB_stat = undefined;
        if (c.mdb_stat(txn, self.dbi_by_hash, &st) != 0) return 0;
        return @intCast(st.ms_entries);
    }
};

// ---- tests ----

const t = std.testing;

test "chunker: determinism and edit locality" {
    const alloc = t.allocator;
    var rng = std.Random.DefaultPrng.init(1234);
    const rand = rng.random();

    var base: [300 * 1024]u8 = undefined;
    rand.bytes(&base);

    var a: std.ArrayList(ChunkEnt) = .empty;
    defer a.deinit(alloc);
    try chunkSlice(alloc, &base, 0, &a);
    var total: u64 = 0;
    for (a.items) |e| total += e.len;
    try t.expectEqual(@as(u64, base.len), total);
    // Chunk sizes are bounded.
    for (a.items) |e| {
        try t.expect(e.len > 0 and e.len <= max_chunk);
    }

    // Edit: replace 2 KiB in the middle.  All chunks fully outside an
    // edit-neighborhood must keep (off, len, hash).
    var edited: [300 * 1024]u8 = undefined;
    @memcpy(&edited, &base);
    rand.bytes(edited[150 * 1024 .. 150 * 1024 + 2048]);
    var b: std.ArrayList(ChunkEnt) = .empty;
    defer b.deinit(alloc);
    try chunkSlice(alloc, &edited, 0, &b);
    var shared: usize = 0;
    for (b.items) |e| {
        for (a.items) |e0| {
            if (e0.off == e.off and e0.len == e.len and std.mem.eql(u8, &e0.hash, &e.hash)) {
                shared += 1;
                break;
            }
        }
    }
    // Nearly every chunk survives a 2 KiB mid-file edit.
    try t.expect(shared >= b.items.len - 4);
}

test "chunker: insertion shifts only local boundaries" {
    const alloc = t.allocator;
    var rng = std.Random.DefaultPrng.init(77);
    const rand = rng.random();
    var base: [200 * 1024]u8 = undefined;
    rand.bytes(&base);

    // Insert 1000 bytes at 50 KiB.
    var edited: [201 * 1024]u8 = undefined;
    @memcpy(edited[0 .. 50 * 1024], base[0 .. 50 * 1024]);
    rand.bytes(edited[50 * 1024 .. 50 * 1024 + 1000]);
    @memcpy(edited[50 * 1024 + 1000 ..][0 .. base.len - 50 * 1024], base[50 * 1024 ..]);

    var a: std.ArrayList(ChunkEnt) = .empty;
    defer a.deinit(alloc);
    try chunkSlice(alloc, &base, 0, &a);
    var b: std.ArrayList(ChunkEnt) = .empty;
    defer b.deinit(alloc);
    try chunkSlice(alloc, &edited, 0, &b);

    // Content-defined: same CONTENT chunks reappear (offset differs past
    // the insertion, so match by hash only) — the copied tail must dedup.
    var content_shared: usize = 0;
    for (b.items) |e| {
        for (a.items) |e0| {
            if (e0.len == e.len and std.mem.eql(u8, &e0.hash, &e.hash)) {
                content_shared += 1;
                break;
            }
        }
    }
    // The 100 KiB region AFTER the insertion should resynchronize and
    // dedup almost fully.
    try t.expect(content_shared * max_chunk >= 150 * 1024);
}

fn withIndex(alloc: Allocator, tmp: *std.testing.TmpDir, body: *const fn (idx: *Index) anyerror!void) !void {
    const state = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(state);
    var idx = try Index.open(alloc, state);
    defer idx.close();
    try body(&idx);
}

test "index: add, lookup, replace, remove" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const S = struct {
        fn run(idx: *Index) !void {
            const chunks = [_]ChunkEnt{
                .{ .off = 0, .len = 100, .hash = [_]u8{1} ** 16 },
                .{ .off = 100, .len = 200, .hash = [_]u8{2} ** 16 },
            };
            try idx.addPath("a/b.bin", &chunks);
            // Shared content in a second path: by_hash lists both.
            try idx.addPath("c/d.bin", &[_]ChunkEnt{
                .{ .off = 5000, .len = 100, .hash = [_]u8{1} ** 16 },
            });
            try t.expectEqual(@as(u64, 3), idx.chunkCount());

            var cands: [8]Cand = undefined;
            const hash1 = [_]u8{1} ** 16;
            const n = try idx.lookup(&hash1, &cands);
            try t.expectEqual(@as(usize, 2), n);
            // Re-add replaces: a/b.bin's old chunks must not linger.
            try idx.addPath("a/b.bin", &[_]ChunkEnt{
                .{ .off = 0, .len = 50, .hash = [_]u8{9} ** 16 },
            });
            const hash2 = [_]u8{2} ** 16;
            const n2 = try idx.lookup(&hash2, &cands);
            try t.expectEqual(@as(usize, 0), n2);
            const n3 = try idx.lookup(&hash1, &cands);
            try t.expectEqual(@as(usize, 1), n3);
            try t.expectEqual(@as(u64, 5000), cands[0].off);
            try t.expectEqualStrings("c/d.bin", cands[0].path);

            try idx.removePath("c/d.bin");
            const n4 = try idx.lookup(&hash1, &cands);
            try t.expectEqual(@as(usize, 0), n4);
        }
    };
    try withIndex(alloc, &tmp, S.run);
}

test "index: sweep evicts dead paths only" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const S = struct {
        fn live(ctx: *const anyopaque, path: []const u8) bool {
            const prefix: []const u8 = @ptrCast(@alignCast(ctx));
            _ = prefix;
            return !std.mem.eql(u8, path, "gone.bin");
        }
        fn run(idx: *Index) !void {
            try idx.addPath("keep.bin", &[_]ChunkEnt{.{ .off = 0, .len = 10, .hash = [_]u8{1} ** 16 }});
            try idx.addPath("gone.bin", &[_]ChunkEnt{.{ .off = 0, .len = 10, .hash = [_]u8{2} ** 16 }});
            const n = try idx.sweep(t.allocator, @ptrCast(&@as(u8, 0)), live);
            try t.expectEqual(@as(usize, 1), n);
            var cands: [4]Cand = undefined;
            const h1 = [_]u8{1} ** 16;
            const h2 = [_]u8{2} ** 16;
            try t.expectEqual(@as(usize, 1), try idx.lookup(&h1, &cands));
            try t.expectEqual(@as(usize, 0), try idx.lookup(&h2, &cands));
            try t.expectEqual(@as(u64, 1), idx.chunkCount());
        }
    };
    try withIndex(alloc, &tmp, S.run);
}

test "index: renamePath and renamePrefix re-key without data churn" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const S = struct {
        fn run(idx: *Index) !void {
            try idx.addPath("dir/a.bin", &[_]ChunkEnt{
                .{ .off = 0, .len = 10, .hash = [_]u8{1} ** 16 },
                .{ .off = 10, .len = 10, .hash = [_]u8{2} ** 16 },
            });
            try idx.addPath("dir/sub/b.bin", &[_]ChunkEnt{
                .{ .off = 0, .len = 10, .hash = [_]u8{3} ** 16 },
            });
            try idx.addPath("other.bin", &[_]ChunkEnt{
                .{ .off = 0, .len = 10, .hash = [_]u8{4} ** 16 },
            });

            try idx.renamePath(t.allocator, "dir/a.bin", "dir/z.bin");
            var cands: [8]Cand = undefined;
            const h1 = [_]u8{1} ** 16;
            try t.expectEqual(@as(usize, 1), try idx.lookup(&h1, &cands));
            try t.expectEqualStrings("dir/z.bin", cands[0].path);

            // Dir rename: everything under dir/ moves to moved/.
            try idx.renamePrefix(t.allocator, "dir", "moved");
            const h3 = [_]u8{3} ** 16;
            try t.expectEqual(@as(usize, 1), try idx.lookup(&h3, &cands));
            try t.expectEqualStrings("moved/sub/b.bin", cands[0].path);
            try t.expectEqual(@as(usize, 1), try idx.lookup(&h1, &cands));
            try t.expectEqualStrings("moved/z.bin", cands[0].path);
            // Unrelated prefix untouched.
            const h4 = [_]u8{4} ** 16;
            try t.expectEqual(@as(usize, 1), try idx.lookup(&h4, &cands));
        }
    };
    try withIndex(alloc, &tmp, S.run);
}

test "hashAndChunkFile large input completes promptly" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var rng = std.Random.DefaultPrng.init(7);
    const data = try alloc.alloc(u8, 300 * 1024 * 1024);
    defer alloc.free(data);
    rng.random().bytes(data);
    try tmp.dir.writeFile(.{ .sub_path = "big.bin", .data = data });
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const abs = try std.fmt.allocPrint(alloc, "{s}/big.bin", .{base});
    defer alloc.free(abs);
    const t0 = std.time.milliTimestamp();
    const dig = try hashAndChunkFile(alloc, abs);
    defer alloc.free(dig.chunks);
    const dt = std.time.milliTimestamp() - t0;
    std.debug.print("hashAndChunkFile 300MiB: {d}ms {d} chunks\n", .{ dt, dig.chunks.len });
    // No time assertion (CI runners vary wildly); the print is the
    // regression tripwire — the T13 failure mode was ~420 s/GiB.
    try t.expect(dig.chunks.len > 0);
}

test "EVP whole-file digest equals std sha256" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var rng = std.Random.DefaultPrng.init(31337);
    var data: [100_000]u8 = undefined;
    rng.random().bytes(&data);
    try tmp.dir.writeFile(.{ .sub_path = "x.bin", .data = &data });
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const abs = try std.fmt.allocPrint(alloc, "{s}/x.bin", .{base});
    defer alloc.free(abs);

    var h = try EvpCtx.init();
    defer h.deinit();
    const fd = try posix.open(abs, .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(fd);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try posix.read(fd, &buf);
        if (n == 0) break;
        try h.update(buf[0..n]);
    }
    var got: [32]u8 = undefined;
    try h.final(&got);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&data, &want, .{});
    try t.expectEqualSlices(u8, &want, &got);
}

test "hashAndChunkFile matches one-shot chunkSlice" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var rng = std.Random.DefaultPrng.init(99);
    var data: [500 * 1024]u8 = undefined;
    rng.random().bytes(&data);

    const abs = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(abs);
    const f = try std.fmt.allocPrint(alloc, "{s}/f.bin", .{abs});
    defer alloc.free(f);
    try tmp.dir.writeFile(.{ .sub_path = "f.bin", .data = &data });

    const dig = try hashAndChunkFile(alloc, f);
    defer alloc.free(dig.chunks);
    try t.expectEqual(@as(u64, data.len), dig.size);
    var expect_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&data, &expect_sha, .{});
    try t.expectEqualSlices(u8, &expect_sha, &dig.sha256);

    var refc: std.ArrayList(ChunkEnt) = .empty;
    defer refc.deinit(alloc);
    try chunkSlice(alloc, &data, 0, &refc);
    try t.expectEqual(refc.items.len, dig.chunks.len);
    for (refc.items, dig.chunks) |e0, e1| {
        try t.expectEqual(e0.off, e1.off);
        try t.expectEqual(e0.len, e1.len);
        try t.expectEqualSlices(u8, &e0.hash, &e1.hash);
    }
}

test "verifyChunkAt catches stale candidates" {
    const alloc = t.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var payload: [4096]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast((i *% 7 +% 13) & 0xff);
    try tmp.dir.writeFile(.{ .sub_path = "s.bin", .data = &payload });
    const base = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(base);
    const abs = try std.fmt.allocPrint(alloc, "{s}/s.bin", .{base});
    defer alloc.free(abs);

    var digest: [32]u8 = undefined;
    const region = payload[1000..2000];
    std.crypto.hash.Blake3.hash(region, &digest, .{});
    var h: [16]u8 = [_]u8{0} ** 16;
    @memcpy(&h, digest[0..16]);
    try t.expect(verifyChunkAt(abs, 1000, 1000, &h));
    // Wrong offset -> mismatch.
    try t.expect(!verifyChunkAt(abs, 1001, 1000, &h));
    // Tamper with the file -> verify fails (stale index entry simulation).
    payload[2000 - 1] = 7;
    try tmp.dir.writeFile(.{ .sub_path = "s.bin", .data = &payload });
    try t.expect(!verifyChunkAt(abs, 1000, 1000, &h));
}
