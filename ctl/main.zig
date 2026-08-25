//! brfsctl — BrFS operator utility.
//!
//! `stats` reads the security.brfs.* sysctl counters (works without a
//! running brfsd; the kernel module is the source).  Everything else talks
//! to brfsd's control socket (/var/run/brfsd.sock — 0600, so run via doas):
//! status, peers, backlog, journal, resync, conflicts list|restore|prune.

const std = @import("std");
const posix = std.posix;
const ctl = @import("brfs_ctl");

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

/// One-shot remote command: connect, send one line, print until EOF.
/// Blocking I/O is right for a CLI (the no-blocking rules govern daemons).
fn cmdRemote(req: []const u8) u8 {
    var addr = std.net.Address.initUnix(ctl.sock_path) catch return 1;
    const fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return 1;
    defer posix.close(fd);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch {
        out("brfsctl: cannot connect to {s} (brfsd not running? permission?)\n", .{ctl.sock_path});
        return 1;
    };
    var off: usize = 0;
    while (off < req.len) {
        off += posix.write(fd, req[off..]) catch return 1;
    }
    posix.shutdown(fd, .send) catch {};
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch return 1;
        if (n == 0) break;
        _ = posix.write(1, buf[0..n]) catch return 1;
    }
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

    const eq = std.mem.eql;
    if (eq(u8, cmd, "status") or eq(u8, cmd, "peers") or eq(u8, cmd, "backlog") or
        eq(u8, cmd, "journal") or eq(u8, cmd, "resync"))
        return cmdRemote(cmd);

    if (eq(u8, cmd, "conflicts")) {
        const sub = args.next() orelse "list";
        if (eq(u8, sub, "list"))
            return cmdRemote("conflicts list");
        if (eq(u8, sub, "restore")) {
            const name = args.next() orelse {
                out("brfsctl: conflicts restore needs a name (see conflicts list)\n", .{});
                return 2;
            };
            var buf: [ctl.max_request]u8 = undefined;
            const req = std.fmt.bufPrint(&buf, "conflicts restore {s}", .{name}) catch return 2;
            return cmdRemote(req);
        }
        if (eq(u8, sub, "prune")) {
            if (args.next()) |filter| {
                var buf: [ctl.max_request]u8 = undefined;
                const req = std.fmt.bufPrint(&buf, "conflicts prune {s}", .{filter}) catch return 2;
                return cmdRemote(req);
            }
            return cmdRemote("conflicts prune");
        }
        out("brfsctl: unknown conflicts subcommand '{s}'\n", .{sub});
        usage();
        return 2;
    }

    if (eq(u8, cmd, "help") or eq(u8, cmd, "--help") or eq(u8, cmd, "-h")) {
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
        "Commands (kernel, no daemon needed):\n" ++
        "  stats                       Show security.brfs.* kernel counters\n" ++
        "\n" ++
        "Commands (control socket, brfsd must run; root):\n" ++
        "  status                      Node state, content-set counts, ring seq\n" ++
        "  peers                       Mesh peers: id, state, direction, wbuf\n" ++
        "  backlog                     Journal/fetch/completion queue depths\n" ++
        "  journal                     Journal stats (moves, echoes, high_seq)\n" ++
        "  resync                      RESYNC_REQ to all peers + local rescan\n" ++
        "  conflicts list              List quarantined (conflict-loser) files\n" ++
        "  conflicts restore <name>    Move a quarantined file back into the tree\n" ++
        "  conflicts prune [substr]    Delete quarantined entries (all or matching)\n" ++
        "  help                        Show this help\n";
    _ = posix.write(1, text) catch {};
}
