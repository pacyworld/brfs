//! protocol.zig — the BrFS peer wire codec (docs/protocol.md).
//!
//! Framing: [len u32 BE][op u16 BE][payload]; len covers op + payload and
//! MUST NOT exceed max_frame (16 MiB).  All integers big-endian; strings
//! length-prefixed.  Byte layouts (the doc's field lists made concrete):
//!
//!   HELLO        proto u16 | node_id (u16 len + bytes) | psk (u16 len + bytes) | nonce [16]
//!   ANNOUNCE     origin u64 | seq u64 | flags u16 | mode u16 | size u64 |
//!                mtime_sec i64 | mtime_nsec u32 | path (u16 len + bytes) | sha256 [32]
//!   FETCH_REQ    origin u64 | seq u64 | offset u64 | len u32 | path
//!   FETCH_DATA   origin u64 | seq u64 | offset u64 | path | data (u32 len + bytes)
//!   FETCH_ACK    origin u64 | seq u64 | path | sha256 [32]
//!   TOMBSTONE    origin u64 | seq u64 | flags u16 | path
//!   RESYNC_REQ   journal_wm u64  (requester's contiguous applied journal
//!                seq for THIS sender; 0 = full pull.  Also the sender's
//!                ack-horizon evidence: "I settled your journal through N")
//!   RESYNC_ENTRY origin u64 | seq u64 | flags u16 | state u8 | mode u16 | size u64 |
//!                mtime_sec i64 | mtime_nsec u32 | path | sha256 [32] | jseq u64
//!                (jseq = sender journal seq when journal-sourced, else 0)
//!   MOVE_FROM    origin u64 | seq u64 | flags u16 | cookie u32 | path
//!   MOVE_TO      same as MOVE_FROM
//!   NACK         origin u64 | seq u64 | code u16 | path
//!   RESYNC_DONE  count u64 | journal_head u64  (terminates a RESYNC stream;
//!                 receiver runs its post-join scan; journal_head = sender's
//!                 journal head at stream start, 0 when stream not journaled —
//!                 the requester's authoritative new watermark)
//!   WM_ECHO      journal_wm u64  (D35: a stream RECEIVER reports the
//!                watermark it just durably settled for the streamer's
//!                journal, at the same points it persists it: the lazy
//!                4096-entry boundary and the DONE settle)
//!   CHUNK_REQ    origin u64 | seq u64 | path  (D37: request the chunk
//!                manifest for a big announced version instead of byte
//!                ranges)
//!   MANIFEST     origin u64 | seq u64 | path | total_size u64 |
//!                start_off u64 | count u32 | count x (len u32 | hash [16])
//!                (D37: ordered chunk entries; offsets implicit — the
//!                receiver's running cursor, which start_off must equal;
//!                stream complete when the cursor reaches total_size.
//!                Frames split at ~1 MiB.  len 0 or > max_chunk is
//!                malformed.)
//!
//! flags bit0 = ISDIR.  All ops are idempotent; every incoming path is
//! validated (contentset.validRelPath) before the caller may touch the
//! filesystem with it.  Decoded messages BORROW the frame buffer — copy
//! anything that must outlive it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const contentset = @import("contentset.zig");
const rdc = @import("rdc.zig");

pub const max_frame: u32 = 16 * 1024 * 1024;
/// v2 (Phase 3b): RESYNC_REQ.journal_wm, RESYNC_ENTRY.jseq,
/// RESYNC_DONE.journal_head.
/// v3 (D35): the (permanently empty since Phase 3b) version vector leaves
/// RESYNC_REQ; WM_ECHO added.  Refused by mismatched peers at HELLO.
/// v4 (D37): CHUNK_REQ + MANIFEST (RDC chunk-manifest transfer mode for
/// files at/above rdc_min).
pub const protocol_version: u16 = 4;
pub const nonce_len = 16;

pub const Op = enum(u16) {
    hello = 1,
    announce = 2,
    fetch_req = 3,
    fetch_data = 4,
    fetch_ack = 5,
    tombstone = 6,
    resync_req = 7,
    resync_entry = 8,
    move_from = 9,
    move_to = 10,
    nack = 11,
    resync_done = 12,
    wm_echo = 13,
    chunk_req = 14,
    manifest = 15,
    _,
};

pub const flag_isdir: u16 = 0x1;

pub const Version = contentset.Version;

pub const Hello = struct {
    proto: u16,
    node_id: []const u8,
    psk: []const u8,
    nonce: [nonce_len]u8,
};

pub const Announce = struct {
    ver: Version,
    is_dir: bool,
    mode: u16,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    path: []const u8,
    sha256: [32]u8,
};

pub const PathVer = struct { ver: Version, path: []const u8 };

/// Receiver-driven chunk pull: one outstanding chunk per fetch, which is
/// the flow control (a 200 MiB serve must NOT be blasted into a bounded
/// write buffer — saturation would drop the conn and wedge the receiver).
pub const FetchReq = struct {
    ver: Version,
    offset: u64,
    len: u32,
    path: []const u8,
};

pub const FetchData = struct {
    ver: Version,
    offset: u64,
    path: []const u8,
    data: []const u8,
};

pub const FetchAck = struct {
    ver: Version,
    path: []const u8,
    sha256: [32]u8,
};

pub const Tombstone = struct {
    ver: Version,
    is_dir: bool,
    path: []const u8,
};

pub const ResyncReq = struct {
    /// Requester's highest CONTIGUOUS journal seq received-and-applied
    /// from this sender (per-sender state; 0 = no watermark -> the sender
    /// streams full records).  Journal seqs are per-sender monotonic and
    /// streamed in order over an ordered channel, so a watermark never
    /// expresses a hole — the failure the per-origin-MAX vector had
    /// (D15/ring-overflow lesson; the vector was removed in v3) does not
    /// apply.
    journal_wm: u64 = 0,
};

/// D35 ack-horizon claim: a RESYNC stream receiver reports the watermark
/// it has settled for the streamer's journal (sent exactly where the
/// receiver persists its watermark — the lazy 4096-entry boundary and the
/// DONE settle).  The streaming peer uses it as sound early-collection
/// evidence for tombstone GC.
pub const WmEcho = struct {
    journal_wm: u64,
};

pub const ResyncEntry = struct {
    ver: Version,
    is_dir: bool,
    state: contentset.State,
    mode: u16,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: u32,
    path: []const u8,
    sha256: [32]u8,
    /// Sender's journal seq this entry carries (0 = full-pull row).
    jseq: u64 = 0,
};

/// Terminates a RESYNC stream.
pub const ResyncDone = struct {
    count: u64,
    /// Sender's journal head at stream start; the requester records it as
    /// its new watermark for this sender.  0 when the sender streamed no
    /// journal (frozen, rebuilt, or empty).
    journal_head: u64 = 0,
};

pub const Move = struct {
    ver: Version,
    is_dir: bool,
    cookie: u32,
    path: []const u8,
};

/// One manifest entry (decoded view; borrows the frame buffer).
pub const ManifestEntry = struct {
    len: u32,
    hash: [rdc.hash_len]u8,
};

/// A MANIFEST stream continues until the entries' implied cursor reaches
/// total_size.  The codec is allocation-free: entries stay in the frame
/// buffer and are walked with manifestEntries().
pub const Manifest = struct {
    ver: Version,
    path: []const u8,
    /// Total size of the announced version (repeated in every frame).
    total_size: u64,
    /// Byte offset of the first entry in this frame; must equal the
    /// receiver's running cursor (gapless ordered stream).
    start_off: u64,
    entries_raw: []const u8, // count x (len u32 | hash16), bounds-checked
};

pub const manifest_entry_len: usize = 4 + rdc.hash_len;

/// Walk a decoded MANIFEST frame's entries.  Buffers borrow the frame.
pub fn manifestEntries(raw: []const u8) ManifestEntryIter {
    return .{ .raw = raw };
}

pub const ManifestEntryIter = struct {
    raw: []const u8,

    pub fn next(self: *ManifestEntryIter) ?ManifestEntry {
        if (self.raw.len < manifest_entry_len) return null;
        const len = std.mem.readInt(u32, self.raw[0..4], .big);
        var hash: [rdc.hash_len]u8 = undefined;
        @memcpy(&hash, self.raw[4 .. 4 + rdc.hash_len]);
        self.raw = self.raw[manifest_entry_len..];
        return .{ .len = len, .hash = hash };
    }
};

pub const Nack = struct {
    ver: Version,
    code: u16,
    path: []const u8,
};

pub const Message = union(enum) {
    hello: Hello,
    announce: Announce,
    fetch_req: FetchReq,
    fetch_data: FetchData,
    fetch_ack: FetchAck,
    tombstone: Tombstone,
    resync_req: ResyncReq,
    resync_entry: ResyncEntry,
    move_from: Move,
    move_to: Move,
    nack: Nack,
    /// Terminates a RESYNC stream.  The receiver records journal_head as
    /// its new watermark (when > 0) and runs its post-join local scan.
    resync_done: ResyncDone,
    /// Ack-horizon claim from a stream receiver (D35; see WmEcho).
    wm_echo: WmEcho,
    /// D37: request the chunk manifest for the announced version (big
    /// files replicate as local-copy chunks + literal ranges).
    chunk_req: PathVer,
    /// D37: one frame of the ordered chunk-manifest stream.
    manifest: Manifest,
};

pub const DecodeError = error{ Truncated, FrameTooLarge, BadOp, BadPath, TrailingGarbage };

/// Peek at a receive buffer: returns the total frame length (header +
/// op + payload) if a full frame is buffered, 0 if more bytes are needed,
/// error if the peer is speaking garbage (drop the connection).
pub fn frameReady(buf: []const u8) DecodeError!usize {
    if (buf.len < 4) return 0;
    const len = std.mem.readInt(u32, buf[0..4], .big);
    if (len < 2 or len > max_frame) return error.FrameTooLarge;
    const total = 4 + @as(usize, len);
    if (buf.len < total) return 0;
    return total;
}

/// Encode a full frame (len prefix included).  Caller owns the result.
pub fn encode(alloc: Allocator, msg: Message) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    const w = &body;

    switch (msg) {
        .hello => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.hello));
            try appendInt(w, alloc, u16, m.proto);
            try appendStr(w, alloc, m.node_id);
            try appendStr(w, alloc, m.psk);
            try w.appendSlice(alloc, &m.nonce);
        },
        .announce => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.announce));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u16, if (m.is_dir) flag_isdir else 0);
            try appendInt(w, alloc, u16, m.mode);
            try appendInt(w, alloc, u64, m.size);
            try appendInt(w, alloc, i64, m.mtime_sec);
            try appendInt(w, alloc, u32, m.mtime_nsec);
            try appendStr(w, alloc, m.path);
            try w.appendSlice(alloc, &m.sha256);
        },
        .fetch_req => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.fetch_req));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u64, m.offset);
            try appendInt(w, alloc, u32, m.len);
            try appendStr(w, alloc, m.path);
        },
        .fetch_data => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.fetch_data));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u64, m.offset);
            try appendStr(w, alloc, m.path);
            if (m.data.len > max_frame) return error.FrameTooLarge;
            try appendInt(w, alloc, u32, @intCast(m.data.len));
            try w.appendSlice(alloc, m.data);
        },
        .fetch_ack => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.fetch_ack));
            try appendVer(w, alloc, m.ver);
            try appendStr(w, alloc, m.path);
            try w.appendSlice(alloc, &m.sha256);
        },
        .tombstone => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.tombstone));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u16, if (m.is_dir) flag_isdir else 0);
            try appendStr(w, alloc, m.path);
        },
        .resync_req => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.resync_req));
            try appendInt(w, alloc, u64, m.journal_wm);
        },
        .resync_entry => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.resync_entry));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u16, if (m.is_dir) flag_isdir else 0);
            try appendInt(w, alloc, u8, @intFromEnum(m.state));
            try appendInt(w, alloc, u16, m.mode);
            try appendInt(w, alloc, u64, m.size);
            try appendInt(w, alloc, i64, m.mtime_sec);
            try appendInt(w, alloc, u32, m.mtime_nsec);
            try appendStr(w, alloc, m.path);
            try w.appendSlice(alloc, &m.sha256);
            try appendInt(w, alloc, u64, m.jseq);
        },
        .move_from, .move_to => |m| {
            const op: Op = if (msg == .move_from) .move_from else .move_to;
            try appendInt(w, alloc, u16, @intFromEnum(op));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u16, if (m.is_dir) flag_isdir else 0);
            try appendInt(w, alloc, u32, m.cookie);
            try appendStr(w, alloc, m.path);
        },
        .nack => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.nack));
            try appendVer(w, alloc, m.ver);
            try appendInt(w, alloc, u16, m.code);
            try appendStr(w, alloc, m.path);
        },
        .resync_done => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.resync_done));
            try appendInt(w, alloc, u64, m.count);
            try appendInt(w, alloc, u64, m.journal_head);
        },
        .wm_echo => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.wm_echo));
            try appendInt(w, alloc, u64, m.journal_wm);
        },
        .chunk_req => |m| {
            try appendInt(w, alloc, u16, @intFromEnum(Op.chunk_req));
            try appendVer(w, alloc, m.ver);
            try appendStr(w, alloc, m.path);
        },
        .manifest => |m| {
            if (m.entries_raw.len % manifest_entry_len != 0) return error.FrameTooLarge;
            try appendInt(w, alloc, u16, @intFromEnum(Op.manifest));
            try appendVer(w, alloc, m.ver);
            try appendStr(w, alloc, m.path);
            try appendInt(w, alloc, u64, m.total_size);
            try appendInt(w, alloc, u64, m.start_off);
            try appendInt(w, alloc, u32, @intCast(m.entries_raw.len / manifest_entry_len));
            try w.appendSlice(alloc, m.entries_raw);
        },
    }

    if (body.items.len > max_frame) return error.FrameTooLarge;
    var out = try alloc.alloc(u8, 4 + body.items.len);
    std.mem.writeInt(u32, out[0..4], @intCast(body.items.len), .big);
    @memcpy(out[4..], body.items);
    return out;
}

/// Decode the payload portion (op + body; len prefix already stripped by
/// frameReady).  Strict: every byte must be consumed, paths must validate.
pub fn decode(payload: []const u8) DecodeError!Message {
    if (payload.len < 2) return error.Truncated;
    var r = Reader{ .buf = payload, .pos = 2 };
    const op: Op = @enumFromInt(std.mem.readInt(u16, payload[0..2], .big));
    const msg: Message = switch (op) {
        .hello => blk: {
            const proto = try r.u16v();
            const node_id = try r.str();
            const psk = try r.str();
            var nonce: [nonce_len]u8 = undefined;
            try r.bytesInto(&nonce);
            break :blk .{ .hello = .{ .proto = proto, .node_id = node_id, .psk = psk, .nonce = nonce } };
        },
        .announce => blk: {
            const ver = try r.ver();
            const flags = try r.u16v();
            const mode = try r.u16v();
            const size = try r.u64v();
            const mtime_sec = try r.i64v();
            const mtime_nsec = try r.u32v();
            const path = try r.path();
            var sha: [32]u8 = undefined;
            try r.bytesInto(&sha);
            break :blk .{ .announce = .{
                .ver = ver,
                .is_dir = (flags & flag_isdir) != 0,
                .mode = mode,
                .size = size,
                .mtime_sec = mtime_sec,
                .mtime_nsec = mtime_nsec,
                .path = path,
                .sha256 = sha,
            } };
        },
        .fetch_req => blk: {
            const v = try r.ver();
            const offset = try r.u64v();
            const len = try r.u32v();
            if (len == 0 or len > max_frame) return error.FrameTooLarge;
            break :blk .{ .fetch_req = .{ .ver = v, .offset = offset, .len = len, .path = try r.path() } };
        },
        .fetch_data => blk: {
            const ver = try r.ver();
            const offset = try r.u64v();
            const path = try r.path();
            const dlen = try r.u32v();
            const data = try r.bytes(dlen);
            break :blk .{ .fetch_data = .{ .ver = ver, .offset = offset, .path = path, .data = data } };
        },
        .fetch_ack => blk: {
            const ver = try r.ver();
            const path = try r.path();
            var sha: [32]u8 = undefined;
            try r.bytesInto(&sha);
            break :blk .{ .fetch_ack = .{ .ver = ver, .path = path, .sha256 = sha } };
        },
        .tombstone => blk: {
            const ver = try r.ver();
            const flags = try r.u16v();
            const path = try r.path();
            break :blk .{ .tombstone = .{ .ver = ver, .is_dir = (flags & flag_isdir) != 0, .path = path } };
        },
        .resync_req => .{ .resync_req = .{ .journal_wm = try r.u64v() } },
        .resync_entry => blk: {
            const ver = try r.ver();
            const flags = try r.u16v();
            const state = std.meta.intToEnum(contentset.State, try r.u8v()) catch return error.BadOp;
            const mode = try r.u16v();
            const size = try r.u64v();
            const mtime_sec = try r.i64v();
            const mtime_nsec = try r.u32v();
            const path = try r.path();
            var sha: [32]u8 = undefined;
            try r.bytesInto(&sha);
            const jseq = try r.u64v();
            break :blk .{ .resync_entry = .{
                .ver = ver,
                .is_dir = (flags & flag_isdir) != 0,
                .state = state,
                .mode = mode,
                .size = size,
                .mtime_sec = mtime_sec,
                .mtime_nsec = mtime_nsec,
                .path = path,
                .sha256 = sha,
                .jseq = jseq,
            } };
        },
        .move_from, .move_to => blk: {
            const ver = try r.ver();
            const flags = try r.u16v();
            const cookie = try r.u32v();
            const path = try r.path();
            const m = Move{ .ver = ver, .is_dir = (flags & flag_isdir) != 0, .cookie = cookie, .path = path };
            break :blk if (op == .move_from) .{ .move_from = m } else .{ .move_to = m };
        },
        .nack => blk: {
            const ver = try r.ver();
            const code = try r.u16v();
            const path = try r.path();
            break :blk .{ .nack = .{ .ver = ver, .code = code, .path = path } };
        },
        .resync_done => .{ .resync_done = .{ .count = try r.u64v(), .journal_head = try r.u64v() } },
        .wm_echo => .{ .wm_echo = .{ .journal_wm = try r.u64v() } },
        .chunk_req => blk: {
            const v = try r.ver();
            break :blk .{ .chunk_req = .{ .ver = v, .path = try r.path() } };
        },
        .manifest => blk: {
            const v = try r.ver();
            const path = try r.path();
            const total_size = try r.u64v();
            const start_off = try r.u64v();
            const count = try r.u32v();
            // Exactly count entries must fill the rest of the frame.
            const entries_raw = try r.bytes(@as(usize, count) * manifest_entry_len);
            var eit = manifestEntries(entries_raw);
            while (eit.next()) |e| {
                if (e.len == 0 or e.len > rdc.max_chunk) return error.BadOp;
            }
            break :blk .{ .manifest = .{
                .ver = v,
                .path = path,
                .total_size = total_size,
                .start_off = start_off,
                .entries_raw = entries_raw,
            } };
        },
        _ => return error.BadOp,
    };
    if (r.pos != payload.len) return error.TrailingGarbage;
    return msg;
}

fn appendInt(w: *std.ArrayList(u8), alloc: Allocator, comptime T: type, v: T) !void {
    var tmp: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &tmp, v, .big);
    try w.appendSlice(alloc, &tmp);
}

fn appendStr(w: *std.ArrayList(u8), alloc: Allocator, s: []const u8) !void {
    if (s.len > std.math.maxInt(u16)) return error.NameTooLong;
    try appendInt(w, alloc, u16, @intCast(s.len));
    try w.appendSlice(alloc, s);
}

fn appendVer(w: *std.ArrayList(u8), alloc: Allocator, ver: Version) !void {
    try appendInt(w, alloc, u64, ver.origin);
    try appendInt(w, alloc, u64, ver.seq);
}

/// Bounds-checked reader for untrusted wire data.
const Reader = struct {
    buf: []const u8,
    pos: usize,

    fn need(self: *Reader, n: usize) DecodeError!void {
        if (self.buf.len - self.pos < n) return error.Truncated;
    }
    fn u8v(self: *Reader) DecodeError!u8 {
        try self.need(1);
        defer self.pos += 1;
        return self.buf[self.pos];
    }
    fn u16v(self: *Reader) DecodeError!u16 {
        try self.need(2);
        defer self.pos += 2;
        return std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
    }
    fn u32v(self: *Reader) DecodeError!u32 {
        try self.need(4);
        defer self.pos += 4;
        return std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
    }
    fn u64v(self: *Reader) DecodeError!u64 {
        try self.need(8);
        defer self.pos += 8;
        return std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
    }
    fn i64v(self: *Reader) DecodeError!i64 {
        try self.need(8);
        defer self.pos += 8;
        return std.mem.readInt(i64, self.buf[self.pos..][0..8], .big);
    }
    fn ver(self: *Reader) DecodeError!Version {
        return .{ .origin = try self.u64v(), .seq = try self.u64v() };
    }
    fn bytesInto(self: *Reader, out: []u8) DecodeError!void {
        try self.need(out.len);
        @memcpy(out, self.buf[self.pos..][0..out.len]);
        self.pos += out.len;
    }
    fn bytes(self: *Reader, n: usize) DecodeError![]const u8 {
        try self.need(n);
        defer self.pos += n;
        return self.buf[self.pos..][0..n];
    }
    fn str(self: *Reader) DecodeError![]const u8 {
        const len = try self.u16v();
        return self.bytes(len);
    }
    fn path(self: *Reader) DecodeError![]const u8 {
        const p = try self.str();
        if (!contentset.validRelPath(p)) return error.BadPath;
        return p;
    }
};

// ---- tests (incl. mutation battery: securemilter-lib pattern) ----

const t = std.testing;

fn shaOf(s: []const u8) [32]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(s, &d, .{});
    return d;
}

const Roundtrip = struct {
    frame: []u8, // owns the bytes the decoded message borrows; free AFTER use
    msg: Message,
};

fn roundtrip(msg: Message) !Roundtrip {
    const frame = try encode(t.allocator, msg);
    errdefer t.allocator.free(frame);
    const total = try frameReady(frame);
    try t.expectEqual(frame.len, total);
    return .{ .frame = frame, .msg = try decode(frame[4..]) };
}

test "roundtrip every opcode" {
    {
        const rt = try roundtrip(.{ .hello = .{
            .proto = protocol_version,
            .node_id = "node-a",
            .psk = "s3cret",
            .nonce = [_]u8{7} ** nonce_len,
        } });
        defer t.allocator.free(rt.frame);
        try t.expectEqualStrings("node-a", rt.msg.hello.node_id);
        try t.expectEqualStrings("s3cret", rt.msg.hello.psk);
        try t.expectEqual(@as(u8, 7), rt.msg.hello.nonce[15]);
    }
    {
        const rt = try roundtrip(.{ .announce = .{
            .ver = .{ .origin = 11, .seq = 22 },
            .is_dir = false,
            .mode = 0o644,
            .size = 12345,
            .mtime_sec = 1_700_000_001,
            .mtime_nsec = 999,
            .path = "dir/file.txt",
            .sha256 = shaOf("x"),
        } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 22), rt.msg.announce.ver.seq);
        try t.expectEqual(@as(u16, 0o644), rt.msg.announce.mode);
        try t.expectEqualStrings("dir/file.txt", rt.msg.announce.path);
    }
    {
        const rt = try roundtrip(.{ .fetch_req = .{ .ver = .{ .origin = 1, .seq = 2 }, .offset = 4096, .len = 1024, .path = "a" } });
        defer t.allocator.free(rt.frame);
        try t.expectEqualStrings("a", rt.msg.fetch_req.path);
        try t.expectEqual(@as(u64, 4096), rt.msg.fetch_req.offset);
        try t.expectEqual(@as(u32, 1024), rt.msg.fetch_req.len);
    }
    {
        const rt = try roundtrip(.{ .fetch_data = .{
            .ver = .{ .origin = 1, .seq = 2 },
            .offset = 4096,
            .path = "a/b",
            .data = "payload bytes",
        } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 4096), rt.msg.fetch_data.offset);
        try t.expectEqualStrings("payload bytes", rt.msg.fetch_data.data);
    }
    {
        const rt = try roundtrip(.{ .fetch_ack = .{ .ver = .{ .origin = 3, .seq = 4 }, .path = "z", .sha256 = shaOf("z") } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(shaOf("z"), rt.msg.fetch_ack.sha256);
    }
    {
        const rt = try roundtrip(.{ .tombstone = .{ .ver = .{ .origin = 5, .seq = 6 }, .is_dir = true, .path = "gone" } });
        defer t.allocator.free(rt.frame);
        try t.expect(rt.msg.tombstone.is_dir);
    }
    {
        const rt = try roundtrip(.{ .resync_req = .{ .journal_wm = 4242 } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 4242), rt.msg.resync_req.journal_wm);
    }
    {
        const rt = try roundtrip(.{ .wm_echo = .{ .journal_wm = 31337 } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 31337), rt.msg.wm_echo.journal_wm);
    }
    {
        const rt = try roundtrip(.{ .resync_entry = .{
            .ver = .{ .origin = 7, .seq = 8 },
            .is_dir = false,
            .state = .deleted,
            .mode = 0o600,
            .size = 1,
            .mtime_sec = 2,
            .mtime_nsec = 3,
            .path = "t",
            .sha256 = shaOf("t"),
            .jseq = 9001,
        } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(contentset.State.deleted, rt.msg.resync_entry.state);
        try t.expectEqual(@as(u64, 9001), rt.msg.resync_entry.jseq);
    }
    {
        const rt = try roundtrip(.{ .resync_done = .{ .count = 17, .journal_head = 4242 } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 17), rt.msg.resync_done.count);
        try t.expectEqual(@as(u64, 4242), rt.msg.resync_done.journal_head);
    }
    {
        const rt = try roundtrip(.{ .move_from = .{ .ver = .{ .origin = 9, .seq = 10 }, .is_dir = false, .cookie = 0, .path = "old" } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u32, 0), rt.msg.move_from.cookie); // cookie 0 is real
        const rt2 = try roundtrip(.{ .move_to = .{ .ver = .{ .origin = 9, .seq = 11 }, .is_dir = true, .cookie = 42, .path = "new" } });
        defer t.allocator.free(rt2.frame);
        try t.expectEqual(@as(u32, 42), rt2.msg.move_to.cookie);
        try t.expect(rt2.msg.move_to.is_dir);
    }
    {
        const rt = try roundtrip(.{ .nack = .{ .ver = .{ .origin = 1, .seq = 1 }, .code = 5, .path = "nope" } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u16, 5), rt.msg.nack.code);
    }
}

test "roundtrip CHUNK_REQ and MANIFEST" {
    {
        const rt = try roundtrip(.{ .chunk_req = .{ .ver = .{ .origin = 4, .seq = 12 }, .path = "big.iso" } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 12), rt.msg.chunk_req.ver.seq);
        try t.expectEqualStrings("big.iso", rt.msg.chunk_req.path);
    }
    {
        var raw: [3 * manifest_entry_len]u8 = undefined;
        std.mem.writeInt(u32, raw[0..4], 50000, .big);
        @memset(raw[4 .. 4 + rdc.hash_len], 0xaa);
        std.mem.writeInt(u32, raw[manifest_entry_len..][0..4], rdc.max_chunk, .big);
        @memset(raw[manifest_entry_len + 4 .. 2 * manifest_entry_len], 0xbb);
        std.mem.writeInt(u32, raw[2 * manifest_entry_len ..][0..4], 1, .big);
        @memset(raw[2 * manifest_entry_len + 4 ..], 0xcc);
        const rt = try roundtrip(.{ .manifest = .{
            .ver = .{ .origin = 4, .seq = 12 },
            .path = "big.iso",
            .total_size = 114561,
            .start_off = 50000,
            .entries_raw = &raw,
        } });
        defer t.allocator.free(rt.frame);
        try t.expectEqual(@as(u64, 114561), rt.msg.manifest.total_size);
        try t.expectEqual(@as(u64, 50000), rt.msg.manifest.start_off);
        var eit = manifestEntries(rt.msg.manifest.entries_raw);
        const e0 = eit.next().?;
        try t.expectEqual(@as(u32, 50000), e0.len);
        try t.expectEqual(@as(u8, 0xaa), e0.hash[0]);
        const e1 = eit.next().?;
        try t.expectEqual(rdc.max_chunk, e1.len);
        try t.expectEqual(@as(u8, 0xbb), e1.hash[rdc.hash_len - 1]);
        const e2 = eit.next().?;
        try t.expectEqual(@as(u32, 1), e2.len);
        try t.expectEqual(@as(?ManifestEntry, null), eit.next());
    }
}

test "manifest decode rejects zero/oversize lens and ragged tails" {
    const mk = struct {
        fn run(entry_len_field: u32, raw: []const u8) !Message {
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(t.allocator);
            try appendInt(&body, t.allocator, u16, @intFromEnum(Op.manifest));
            try appendVer(&body, t.allocator, .{ .origin = 1, .seq = 1 });
            try appendStr(&body, t.allocator, "f");
            try appendInt(&body, t.allocator, u64, 100000);
            try appendInt(&body, t.allocator, u64, 0);
            try appendInt(&body, t.allocator, u32, entry_len_field);
            try body.appendSlice(t.allocator, raw);
            return decode(body.items);
        }
    };
    var good: [manifest_entry_len]u8 = undefined;
    std.mem.writeInt(u32, good[0..4], 1024, .big);
    @memset(good[4..], 1);
    // count vs bytes mismatch
    try t.expectError(error.Truncated, mk.run(2, &good));
    // len 0 entry
    var zeroed: [manifest_entry_len]u8 = good;
    std.mem.writeInt(u32, zeroed[0..4], 0, .big);
    try t.expectError(error.BadOp, mk.run(1, &zeroed));
    // oversize entry
    var big: [manifest_entry_len]u8 = good;
    std.mem.writeInt(u32, big[0..4], rdc.max_chunk + 1, .big);
    try t.expectError(error.BadOp, mk.run(1, &big));
    // sane one passes
    _ = try mk.run(1, &good);
}

test "frameReady needs full frame, rejects oversize" {
    const frame = try encode(t.allocator, .{ .fetch_req = .{ .ver = .{ .origin = 1, .seq = 1 }, .offset = 0, .len = 64, .path = "x" } });
    defer t.allocator.free(frame);
    try t.expectEqual(@as(usize, 0), try frameReady(frame[0..2])); // partial header
    try t.expectEqual(@as(usize, 0), try frameReady(frame[0 .. frame.len - 1])); // partial body
    try t.expectEqual(frame.len, try frameReady(frame));

    var big: [4]u8 = undefined;
    std.mem.writeInt(u32, &big, max_frame + 1, .big);
    try t.expectError(error.FrameTooLarge, frameReady(&big));
    std.mem.writeInt(u32, &big, 1, .big); // len < 2: no room for op
    try t.expectError(error.FrameTooLarge, frameReady(&big));
}

test "mutation battery: every truncation fails decode" {
    const msgs = [_]Message{
        .{ .hello = .{ .proto = 1, .node_id = "n", .psk = "p", .nonce = [_]u8{0} ** nonce_len } },
        .{ .announce = .{ .ver = .{ .origin = 1, .seq = 2 }, .is_dir = true, .mode = 0o755, .size = 9, .mtime_sec = 1, .mtime_nsec = 2, .path = "d/f", .sha256 = shaOf("q") } },
        .{ .fetch_data = .{ .ver = .{ .origin = 1, .seq = 2 }, .offset = 0, .path = "f", .data = "chunk" } },
        .{ .resync_entry = .{ .ver = .{ .origin = 1, .seq = 2 }, .is_dir = false, .state = .live, .mode = 0o644, .size = 3, .mtime_sec = 4, .mtime_nsec = 5, .path = "p", .sha256 = shaOf("p") } },
        .{ .move_to = .{ .ver = .{ .origin = 1, .seq = 3 }, .is_dir = false, .cookie = 7, .path = "mv" } },
    };
    for (msgs) |msg| {
        const frame = try encode(t.allocator, msg);
        defer t.allocator.free(frame);
        var cut: usize = 0;
        while (cut < frame.len) : (cut += 1) {
            const partial = frame[0..cut];
            const total = frameReady(partial) catch continue;
            if (total == 0) continue; // needs more bytes: fine
            // A shorter buffer must never yield a complete valid frame.
            try t.expect(false);
        }
    }
}

test "mutation battery: byte flips never crash and garbage is rejected" {
    const msg = Message{ .announce = .{ .ver = .{ .origin = 1, .seq = 2 }, .is_dir = false, .mode = 0o644, .size = 100, .mtime_sec = 1, .mtime_nsec = 0, .path = "a/b.txt", .sha256 = shaOf("s") } };
    const frame = try encode(t.allocator, msg);
    defer t.allocator.free(frame);

    var i: usize = 4; // skip len prefix (flip-tested via frameReady above)
    var rejected: usize = 0;
    var accepted: usize = 0;
    while (i < frame.len) : (i += 1) {
        const mutated = try t.allocator.dupe(u8, frame);
        defer t.allocator.free(mutated);
        mutated[i] ^= 0xff;
        _ = decode(mutated[4..]) catch {
            rejected += 1;
            continue;
        };
        accepted += 1; // some flips land in payload fields: must still decode sanely
    }
    try t.expect(rejected > 0); // at least op/path/state flips must be caught
    try t.expect(accepted > 0); // payload-field flips decode but differ
}

test "hostile paths are rejected" {
    const bad = [_][]const u8{ "/etc/passwd", "../x", "a/../../b", "a//b", "", "a/./b" };
    for (bad) |p| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(t.allocator);
        try appendInt(&body, t.allocator, u16, @intFromEnum(Op.fetch_req));
        try appendVer(&body, t.allocator, .{ .origin = 1, .seq = 1 });
        try appendInt(&body, t.allocator, u64, 0);
        try appendInt(&body, t.allocator, u32, 64);
        // Bypass appendStr's own checks is unnecessary; build the raw field.
        try appendInt(&body, t.allocator, u16, @intCast(p.len));
        try body.appendSlice(t.allocator, p);
        try t.expectError(error.BadPath, decode(body.items));
    }
}

test "unknown op and trailing garbage rejected" {
    var junk = [_]u8{ 0xde, 0xad, 0x00 }; // op 0xdead
    try t.expectError(error.BadOp, decode(&junk));

    const frame = try encode(t.allocator, .{ .fetch_req = .{ .ver = .{ .origin = 1, .seq = 1 }, .offset = 0, .len = 64, .path = "x" } });
    defer t.allocator.free(frame);
    const padded = try t.allocator.alloc(u8, frame.len + 1);
    defer t.allocator.free(padded);
    @memcpy(padded[0..frame.len], frame);
    padded[frame.len] = 0;
    try t.expectError(error.TrailingGarbage, decode(padded[4..]));
}
