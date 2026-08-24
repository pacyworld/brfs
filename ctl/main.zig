//! brfsctl — BrFS operator utility.
//!
//! Implemented now: `stats` — reads the security.brfs.* sysctl counters
//! (works without a running brfsd; the kernel module is the source).
//! Phase 1 adds the brfsd control socket (/var/run/brfsd.sock) commands:
//! status, peers, backlog, resync, conflicts.

const std = @import("std");
const posix = std.posix;

extern "c" fn sysctlbyname(
    name: [*:0]const u8,
    oldp: ?*anyopaque,
    oldlenp: ?*usize,
    newp: ?*const anyopaque,
    newlen: usize,
) c_int;

fn readU64(name: [*:0]const u8) ?u64 {
    var val: u64 = 0;
    var len: usize = @sizeOf(u64);
    if (sysctlbyname(name, &val, &len, null, 0) != 0)
        return null;
    return val;
}

fn readInt(name: [*:0]const u8) ?i32 {
    var val: i32 = 0;
    var len: usize = @sizeOf(i32);
    if (sysctlbyname(name, &val, &len, null, 0) != 0)
        return null;
    return val;
}

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = posix.write(1, msg) catch {};
}

fn cmdStats() u8 {
    const events = readU64("security.brfs.event_count") orelse {
        out("brfs.ko is not loaded (security.brfs.* unavailable)\n", .{});
        return 1;
    };
    const drops = readU64("security.brfs.ring_drops") orelse 0;
    const ring_size = readInt("security.brfs.ring_size") orelse 0;
    const enabled = readInt("security.brfs.enabled") orelse 0;
    out("brfs kernel module:\n", .{});
    out("  enabled:    {d}\n", .{enabled});
    out("  events:     {d}\n", .{events});
    out("  ring drops: {d}\n", .{drops});
    out("  ring size:  {d}\n", .{ring_size});
    return 0;
}

pub fn main() !u8 {
    var args = std.process.args();
    _ = args.skip();
    const cmd = args.next() orelse {
        usage();
        return 2;
    };

    if (std.mem.eql(u8, cmd, "stats"))
        return cmdStats();

    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or
        std.mem.eql(u8, cmd, "-h"))
    {
        usage();
        return 0;
    }

    out("brfsctl: unknown command '{s}'\n", .{cmd});
    usage();
    return 2;
}

fn usage() void {
    const text =
        "usage: brfsctl <command>\n" ++
        "\n" ++
        "Commands:\n" ++
        "  stats    Show security.brfs.* kernel counters\n" ++
        "  help     Show this help\n";
    _ = posix.write(1, text) catch {};
}
