//! brfsd — BrFS replication daemon.
//!
//! Thin entry point: config, PSK, device setup, then the daemon core
//! (daemon.zig): one kqueue loop + one drainer thread owning the ring pop.

const std = @import("std");
const posix = std.posix;
const config = @import("config.zig");
const events = @import("events.zig");
const daemon = @import("daemon.zig");

const default_config_path = "/usr/local/etc/brfs.conf";

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa_state.allocator();

    var config_path: [*:0]const u8 = default_config_path;

    var args = std.process.args();
    _ = args.skip();
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--config=")) {
            config_path = arg[9.. :0];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            const help =
                "usage: brfsd [options]\n" ++
                "\n" ++
                "Options:\n" ++
                "  --config=PATH   Config file (default: " ++ default_config_path ++ ")\n" ++
                "  --help          Show this help\n";
            _ = posix.write(1, help) catch {};
            return;
        }
    }

    const cfg = config.load(config_path) orelse {
        daemon.log(.err, "cannot load config {s}", .{config_path});
        return error.ConfigFailed;
    };
    daemon.log(.info, "node_id={s} path={s} peers={d} primary={}", .{
        cfg.node_id, cfg.replicated_path, cfg.num_peers, cfg.primary,
    });

    var psk: []const u8 = "";
    var psk_buf: []u8 = &.{};
    defer if (psk_buf.len > 0) alloc.free(psk_buf);
    if (cfg.psk_file.len > 0) {
        psk_buf = std.fs.cwd().readFileAlloc(alloc, cfg.psk_file, 4096) catch |err| {
            daemon.log(.err, "cannot read psk_file {s}: {s}", .{ cfg.psk_file, @errorName(err) });
            return error.PskFailed;
        };
        psk = std.mem.trim(u8, psk_buf, " \t\r\n");
        if (psk.len == 0) {
            daemon.log(.err, "psk_file {s} is empty", .{cfg.psk_file});
            return error.PskFailed;
        }
    }

    const dev_fd = events.openDevice() catch |err| {
        daemon.log(.err, "cannot open {s}: {s} (is brfs.ko loaded? stale brfsd?)", .{
            events.dev_path, @errorName(err),
        });
        return err;
    };
    // Not closed on the error paths below on purpose: process exit does it.

    events.addRoot(dev_fd, cfg.replicated_path, 0) catch |err| {
        daemon.log(.err, "ADDROOT {s}: {s}", .{ cfg.replicated_path, @errorName(err) });
        return err;
    };
    daemon.log(.info, "watch root registered: {s}", .{cfg.replicated_path});

    // Drainer wakeup pipe (both ends non-blocking; the core loop drains
    // with EV_CLEAR, the drainer drops wakeups on a full pipe).
    const pfds = try posix.pipe();
    var fl = std.c.fcntl(pfds[0], 3, @as(c_int, 0)); // F_GETFL
    _ = std.c.fcntl(pfds[0], 4, fl | @as(c_int, 0x0004)); // F_SETFL | O_NONBLOCK
    fl = std.c.fcntl(pfds[1], 3, @as(c_int, 0));
    _ = std.c.fcntl(pfds[1], 4, fl | @as(c_int, 0x0004));

    var d = try daemon.Daemon.init(alloc, &cfg, psk, dev_fd, pfds[0], pfds[1]);

    const drainer = try std.Thread.spawn(.{}, daemon.drainerEntry, .{ dev_fd, &d.evq });
    drainer.detach();

    try d.run();
}

test {
    std.testing.refAllDecls(@import("config.zig"));
    std.testing.refAllDecls(@import("events.zig"));
    std.testing.refAllDecls(@import("contentset.zig"));
    std.testing.refAllDecls(@import("journal.zig"));
    std.testing.refAllDecls(@import("protocol.zig"));
    std.testing.refAllDecls(@import("peer.zig"));
    std.testing.refAllDecls(@import("installer.zig"));
    std.testing.refAllDecls(@import("resync.zig"));
    std.testing.refAllDecls(@import("server.zig"));
    std.testing.refAllDecls(@import("ctl.zig"));
    std.testing.refAllDecls(@import("daemon.zig"));
    std.testing.refAllDecls(@import("tls.zig"));
}
