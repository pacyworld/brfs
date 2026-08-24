//! brfsd — BrFS replication daemon.
//!
//! Phase 0/1 scope: real config parsing (UCL), real /dev/brfs consumption
//! (ioctl root push + kqueue-driven batched drain), real signal handling.
//! The peer protocol, content set, installer, and resync land in Phase 1;
//! this event-drain loop doubles as the P0.2 kmod spike verification tool.

const std = @import("std");
const posix = std.posix;
const config = @import("config.zig");
const events = @import("events.zig");

const default_config_path = "/usr/local/etc/brfs.conf";

const c_event = @cImport({
    @cInclude("sys/event.h");
});

const KEvent = c_event.struct_kevent;

extern "c" fn kqueue() c_int;
extern "c" fn kevent(
    kq: c_int,
    changelist: ?[*]const KEvent,
    nchanges: c_int,
    eventlist: ?[*]KEvent,
    nevents: c_int,
    timeout: ?*const std.c.timespec,
) c_int;

fn makeKevent(ident: usize, filter: c_short, flags: c_ushort, fflags: c_uint) KEvent {
    return KEvent{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = fflags,
        .data = 0,
        .udata = null,
        .ext = [_]u64{ 0, 0, 0, 0 },
    };
}

const Level = enum { info, warn, err };

fn log(comptime level: Level, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "brfsd[" ++ @tagName(level) ++ "]: " ++ fmt ++ "\n", args) catch return;
    _ = posix.write(2, msg) catch {};
}

pub fn main() !void {
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
        log(.err, "cannot load config {s}", .{config_path});
        return error.ConfigFailed;
    };
    log(.info, "node_id={s} path={s} peers={d}", .{
        cfg.node_id, cfg.replicated_path, cfg.num_peers,
    });

    const dev_fd = events.openDevice() catch |err| {
        log(.err, "cannot open {s}: {s} (is brfs.ko loaded?)", .{
            events.dev_path, @errorName(err),
        });
        return err;
    };
    defer posix.close(dev_fd);

    events.addRoot(dev_fd, cfg.replicated_path, 0) catch |err| {
        log(.err, "ADDROOT {s}: {s}", .{ cfg.replicated_path, @errorName(err) });
        return err;
    };
    log(.info, "watch root registered: {s}", .{cfg.replicated_path});

    const kq = kqueue();
    if (kq < 0) {
        log(.err, "kqueue() failed", .{});
        return error.KqueueFailed;
    }

    const changes = [_]KEvent{
        // EV_CLEAR: drain the device fully on each wakeup.
        makeKevent(@intCast(dev_fd), c_event.EVFILT_READ, c_event.EV_ADD | c_event.EV_CLEAR, 0),
        makeKevent(15, c_event.EVFILT_SIGNAL, c_event.EV_ADD, 0), // SIGTERM
        makeKevent(2, c_event.EVFILT_SIGNAL, c_event.EV_ADD, 0), // SIGINT
    };
    var changelist: ?[*]const KEvent = &changes;
    var nchanges: c_int = changes.len;

    var mask = posix.sigemptyset();
    _ = std.c.sigaddset(&mask, 15);
    _ = std.c.sigaddset(&mask, 2);
    _ = std.c.sigprocmask(std.c.SIG.BLOCK, &mask, null);

    log(.info, "event loop started, draining {s}", .{events.dev_path});

    var running = true;
    var evlist: [8]KEvent = undefined;
    var buf: [65536]u8 align(@alignOf(events.Event)) = undefined;

    while (running) {
        const nevents = kevent(kq, changelist, nchanges, &evlist, evlist.len, null);
        changelist = null;
        nchanges = 0;
        if (nevents < 0) {
            if (std.c._errno().* != 4) // EINTR
                log(.err, "kevent wait failed, errno={d}", .{std.c._errno().*});
            continue;
        }

        for (evlist[0..@intCast(nevents)]) |*ev| {
            if (ev.filter == c_event.EVFILT_SIGNAL) {
                log(.info, "signal {d}, shutting down", .{ev.ident});
                running = false;
            } else if (ev.filter == c_event.EVFILT_READ) {
                while (true) {
                    const batch = events.drain(dev_fd, &buf) catch |err| {
                        log(.err, "read {s}: {s}", .{ events.dev_path, @errorName(err) });
                        break;
                    };
                    if (batch.len == 0) break;
                    for (batch) |*bev| {
                        if (bev.abi != events.abi_version) {
                            log(.warn, "ABI mismatch: event v{d}, daemon v{d}", .{
                                bev.abi, events.abi_version,
                            });
                            continue;
                        }
                        if (bev.op == @intFromEnum(events.Op.overflow)) {
                            log(.warn, "RING OVERFLOW seq={d} — tree rescan required", .{bev.seq});
                            continue;
                        }
                        log(.info, "seq={d} op={s} fsid={x} dir={d} file={d} gen={d} cookie={x} {s}{s}", .{
                            bev.seq,
                            events.opName(bev.op),
                            bev.fsid,
                            bev.dir_fileid,
                            bev.fileid,
                            bev.gen,
                            bev.cookie,
                            bev.nameSlice(),
                            if (bev.isDir()) " (dir)" else "",
                        });
                    }
                }
            }
        }
    }

    log(.info, "shutdown complete", .{});
}

test {
    std.testing.refAllDecls(@import("config.zig"));
    std.testing.refAllDecls(@import("events.zig"));
    std.testing.refAllDecls(@import("contentset.zig"));
    std.testing.refAllDecls(@import("journal.zig"));
    std.testing.refAllDecls(@import("protocol.zig"));
}
