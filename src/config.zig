//! brfsd configuration: UCL parsing (base-system privateucl).
//!
//! One source of truth: /usr/local/etc/brfs.conf.  The kernel module never
//! reads this file; brfsd pushes what the kmod needs via ioctl at startup.

const std = @import("std");
const ucl = @import("ucl");
const events = @import("events.zig");

pub const max_peers = 16;

pub const Config = struct {
    node_id: []const u8 = "",
    replicated_path: []const u8 = "",
    state_dir: []const u8 = "/var/db/brfs",
    listen: []const u8 = "",
    psk_file: []const u8 = "",
    peers: [max_peers][]const u8 = undefined,
    num_peers: usize = 0,
    rate_limit: u64 = 0, // bytes/sec, 0 = unlimited
    /// Initial-seed role (gap #8): a primary with an empty content set
    /// treats its local tree as authoritative; a non-primary with an empty
    /// set pulls via RESYNC before announcing anything local.
    primary: bool = false,
    /// TLS/mTLS configuration.  All three paths required to enable TLS.
    /// When set, all peer connections (inbound + outbound) use TLS 1.3
    /// with KTLS offload (if kernel supports it).  The PSK handshake
    /// still runs over the encrypted channel as defense in depth.
    tls_cert: []const u8 = "",
    tls_key: []const u8 = "",
    tls_ca: []const u8 = "",
    /// KTLS offload toggle (escape hatch if kernel TLS misbehaves on a
    /// given kernel/NIC combination).
    tls_ktls: bool = true,
    /// Gap #11: op classes to drop at event intake (selective filtering;
    /// bitmask of events.opBit).  The kmod tap stays emit-all — kernel-side
    /// per-root attribution would need the lineage walk the emit-all
    /// decision rejected — so the filter lives here in the daemon.  Dropped
    /// content classes are recovered by the scan floor, not in real time:
    /// this knob is for shedding noisy classes like ATTRIB (mode/mtime
    /// churn), not for content filtering.  OVERFLOW is never droppable.
    events_drop: u32 = 0,

    /// True when TLS cert+key are configured (enables mTLS on peer conns).
    pub fn tlsEnabled(self: *const Config) bool {
        return self.tls_cert.len > 0 and self.tls_key.len > 0;
    }

    /// Validate cross-field rules that parsing alone cannot catch.
    pub fn validate(self: *const Config) !void {
        if (self.node_id.len == 0)
            return error.MissingNodeId;
        if (self.replicated_path.len == 0 or self.replicated_path[0] != '/')
            return error.BadReplicatedPath;
        if (self.num_peers == 0)
            return error.NoPeers;
        if (self.state_dir.len == 0 or self.state_dir[0] != '/')
            return error.BadStateDir;
        // state_dir inside the watched tree = staging events feed the
        // journal = self-echo storm.  Reject by prefix at component
        // granularity ("/data/x" must not match "/data/xyz").
        if (std.mem.eql(u8, self.state_dir, self.replicated_path))
            return error.StateDirInsideTree;
        if (std.mem.startsWith(u8, self.state_dir, self.replicated_path)) {
            const rest = self.state_dir[self.replicated_path.len..];
            if (rest.len > 0 and rest[0] == '/')
                return error.StateDirInsideTree;
        }
        // Same-filesystem rule (staging rename(2) must not EXDEV) is
        // checked at startup via statfs — it cannot be evaluated here.
    }
};

fn getString(root: ucl.Object, key: [*:0]const u8) ?[]const u8 {
    const obj = root.lookup(key) orelse return null;
    return obj.toString();
}

/// Parse and validate a config file.  Returns null on any failure
/// (caller logs and exits); UCL objects stay owned by the parser,
/// which outlives the returned Config (static lifetime in practice).
pub fn load(path: [*:0]const u8) ?Config {
    const parser = ucl.Parser.init(0) orelse return null;
    if (!parser.addFile(path)) {
        if (parser.getError()) |e|
            std.debug.print("brfsd: config {s}: {s}\n", .{ path, e });
        return null;
    }
    const root = parser.getObject() orelse return null;

    var cfg = Config{};

    if (getString(root, "node_id")) |v| cfg.node_id = v;
    if (getString(root, "replicated_path")) |v| cfg.replicated_path = v;
    if (getString(root, "state_dir")) |v| cfg.state_dir = v;
    if (getString(root, "listen")) |v| cfg.listen = v;
    if (getString(root, "psk_file")) |v| cfg.psk_file = v;
    if (root.lookup("primary")) |obj| cfg.primary = obj.toBool();
    if (getString(root, "tls_cert")) |v| cfg.tls_cert = v;
    if (getString(root, "tls_key")) |v| cfg.tls_key = v;
    if (getString(root, "tls_ca")) |v| cfg.tls_ca = v;
    if (root.lookup("tls_ktls")) |obj| cfg.tls_ktls = obj.toBool();

    if (root.lookup("rate_limit")) |obj| {
        cfg.rate_limit = switch (obj.objectType()) {
            .int_ => @intCast(@max(obj.toInt(), 0)),
            .string => blk: {
                const s = obj.toString() orelse break :blk 0;
                break :blk std.fmt.parseInt(u64, s, 10) catch 0;
            },
            else => 0,
        };
    }

    if (root.lookup("events_drop")) |obj| {
        if (obj.objectType() == .array) {
            var it = obj.iterate();
            while (it.next()) |item| {
                const name = item.toString() orelse continue;
                const op = events.opFromName(name) orelse {
                    std.debug.print("brfsd: config {s}: unknown events_drop op '{s}'\n", .{ path, name });
                    return null;
                };
                if (op == .overflow) {
                    std.debug.print("brfsd: config {s}: events_drop cannot include 'overflow'\n", .{path});
                    return null;
                }
                cfg.events_drop |= events.opBit(op);
            }
        }
    }

    if (root.lookup("peers")) |obj| {
        if (obj.objectType() == .array) {
            var it = obj.iterate();
            while (it.next()) |item| {
                if (cfg.num_peers >= max_peers) break;
                if (item.toString()) |s| {
                    cfg.peers[cfg.num_peers] = s;
                    cfg.num_peers += 1;
                }
            }
        }
    }

    cfg.validate() catch |err| {
        std.debug.print("brfsd: config {s}: {s}\n", .{ path, @errorName(err) });
        return null;
    };
    return cfg;
}

test "config validate rejects empty node_id" {
    var cfg = Config{
        .replicated_path = "/data",
        .num_peers = 1,
    };
    cfg.peers[0] = "10.0.0.2:4590";
    try std.testing.expectError(error.MissingNodeId, cfg.validate());
}

test "config validate rejects relative replicated_path" {
    var cfg = Config{
        .node_id = "a",
        .replicated_path = "data",
        .num_peers = 1,
    };
    cfg.peers[0] = "10.0.0.2:4590";
    try std.testing.expectError(error.BadReplicatedPath, cfg.validate());
}

test "config validate rejects zero peers" {
    const cfg = Config{
        .node_id = "a",
        .replicated_path = "/data",
    };
    try std.testing.expectError(error.NoPeers, cfg.validate());
}

test "config validate accepts minimal good config" {
    var cfg = Config{
        .node_id = "a",
        .replicated_path = "/data",
        .num_peers = 1,
    };
    cfg.peers[0] = "10.0.0.2:4590";
    try cfg.validate();
}

test "config validate rejects state_dir inside the watched tree" {
    var cfg = Config{
        .node_id = "a",
        .replicated_path = "/data/replicated",
        .state_dir = "/data/replicated/.brfs",
        .num_peers = 1,
    };
    cfg.peers[0] = "10.0.0.2:4590";
    try std.testing.expectError(error.StateDirInsideTree, cfg.validate());

    // Same name, exact match:
    cfg.state_dir = "/data/replicated";
    try std.testing.expectError(error.StateDirInsideTree, cfg.validate());

    // Component-granularity: "/data/replicated2" is NOT inside the tree:
    cfg.state_dir = "/data/replicated2/.brfs";
    try cfg.validate();
}
