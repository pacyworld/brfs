//! /dev/brfs consumer: the ONLY change-detection path in brfsd.
//!
//! Mirrors kmod/brfs.h.  The kernel module owns the ring; this module
//! opens the device (single-open enforced in kernel), pushes watch roots
//! via ioctl, and drains events in batches.

const std = @import("std");
const posix = std.posix;

pub const dev_path = "/dev/brfs";
pub const abi_version: u32 = 1;
pub const name_max = 255;

pub const Op = enum(u32) {
    create = 1,
    modify = 2,
    delete = 3,
    move_from = 4,
    move_to = 5,
    attrib = 6,
    overflow = 7,
    _,
};

/// Mirrors struct brfs_event in kmod/brfs.h. Exactly 512 bytes:
/// power-of-two slots for the future mmap'd shared ring. fsid+fileid
/// disambiguate across filesystems; gen guards inode reuse.
pub const Event = extern struct {
    seq: u64,
    fsid: u64,
    dir_fileid: u64,
    fileid: u64,
    gen: u64,
    op: u32,
    cookie: u32,
    flags: u32,
    abi: u32,
    name: [name_max + 1]u8,
    reserved: [25]u64,

    pub fn isDir(self: *const Event) bool {
        return (self.flags & 0x1) != 0;
    }

    pub fn nameSlice(self: *const Event) []const u8 {
        return std.mem.sliceTo(&self.name, 0);
    }
};

const Root = extern struct {
    path: [1024]u8, // MAXPATHLEN
    mask: u32,
    pad: u32,
};

pub const Stats = extern struct {
    events: u64,
    drops: u64,
    ring_count: u64,
    ring_size: u64,
    roots: u32,
    pad: u32,
};

// FreeBSD ioctl encoding: _IOC(dir, group, num, len) =
//   dir | ((len & 0x1fff) << 16) | (group << 8) | num
const IOC_VOID: c_ulong = 0x20000000;
const IOC_IN: c_ulong = 0x80000000;
const IOC_OUT: c_ulong = 0x40000000;
const IOCPARM_MASK: c_ulong = 0x1fff;

fn ioc(comptime dir: c_ulong, comptime T: type, comptime num: u8) c_ulong {
    return dir | ((@as(c_ulong, @sizeOf(T)) & IOCPARM_MASK) << 16) |
        (@as(c_ulong, 'B') << 8) | num;
}

const BRFSIOC_ADDROOT = ioc(IOC_IN, Root, 1);
const BRFSIOC_DELROOT = ioc(IOC_IN, Root, 2);
const BRFSIOC_GETSTATS = ioc(IOC_OUT, Stats, 3);
const BRFSIOC_FLUSH = ioc(IOC_VOID, u0, 4);

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;

pub fn openDevice() !posix.fd_t {
    // BLOCKING on purpose: the drainer thread parks in read() and owns the
    // ring pop side; the core loop never reads the device (ioctls don't
    // block).  Do NOT open O_NONBLOCK and try to clear it later — F_SETFL
    // on a cdev fails with ENOTTY on FreeBSD.
    return posix.open(dev_path, .{ .ACCMODE = .RDWR }, 0);
}

pub fn addRoot(fd: posix.fd_t, path: []const u8, mask: u32) !void {
    if (path.len == 0 or path[0] != '/' or path.len >= 1024)
        return error.BadPath;
    var root = std.mem.zeroes(Root);
    @memcpy(root.path[0..path.len], path);
    root.mask = mask;
    try ioctlChecked(fd, BRFSIOC_ADDROOT, @intFromPtr(&root));
}

pub fn delRoot(fd: posix.fd_t, path: []const u8) !void {
    if (path.len == 0 or path[0] != '/' or path.len >= 1024)
        return error.BadPath;
    var root = std.mem.zeroes(Root);
    @memcpy(root.path[0..path.len], path);
    try ioctlChecked(fd, BRFSIOC_DELROOT, @intFromPtr(&root));
}

pub fn flush(fd: posix.fd_t) !void {
    try ioctlChecked(fd, BRFSIOC_FLUSH, 0);
}

pub fn getStats(fd: posix.fd_t) !Stats {
    var stats = std.mem.zeroes(Stats);
    try ioctlChecked(fd, BRFSIOC_GETSTATS, @intFromPtr(&stats));
    return stats;
}

fn ioctlChecked(fd: posix.fd_t, request: c_ulong, arg: usize) !void {
    if (ioctl(fd, request, arg) != 0) {
        return switch (std.c._errno().*) {
            @intFromEnum(std.c.E.BUSY) => error.DeviceBusy,
            @intFromEnum(std.c.E.EXIST) => error.RootExists,
            @intFromEnum(std.c.E.NOENT) => error.RootMissing,
            @intFromEnum(std.c.E.NOSPC) => error.TooManyRoots,
            @intFromEnum(std.c.E.INVAL) => error.Invalid,
            else => error.IoctlFailed,
        };
    }
}

/// Drain available events into caller buffer; returns events decoded.
/// Buffer must be Event-aligned and a whole multiple of @sizeOf(Event).
/// Device is O_NONBLOCK: an empty ring returns an empty slice.
pub fn drain(fd: posix.fd_t, buf: []align(@alignOf(Event)) u8) ![]const Event {
    const n = posix.read(fd, buf) catch |err| switch (err) {
        error.WouldBlock => return &.{},
        else => return err,
    };
    const count = n / @sizeOf(Event);
    const ptr: [*]const Event = @ptrCast(@alignCast(buf.ptr));
    return ptr[0..count];
}

pub fn opName(op: u32) []const u8 {
    const e: Op = @enumFromInt(op);
    return switch (e) {
        .create => "CREATE",
        .modify => "MODIFY",
        .delete => "DELETE",
        .move_from => "MOVE_FROM",
        .move_to => "MOVE_TO",
        .attrib => "ATTRIB",
        .overflow => "OVERFLOW",
        _ => "UNKNOWN",
    };
}

test "ioctl encodings match C _IOW/_IOR for brfs.h structs" {
    // _IOW('B',1,struct brfs_root): 0x80000000 | (1032<<16) | 0x4200 | 1
    try std.testing.expectEqual(@as(c_ulong, 0x84084201), BRFSIOC_ADDROOT);
    try std.testing.expectEqual(@as(c_ulong, 0x84084202), BRFSIOC_DELROOT);
    // _IOR('B',3,struct brfs_stats): 0x40000000 | (40<<16) | 0x4200 | 3
    try std.testing.expectEqual(@as(c_ulong, 0x40284203), BRFSIOC_GETSTATS);
    // _IO('B',4)
    try std.testing.expectEqual(@as(c_ulong, 0x20004204), BRFSIOC_FLUSH);
}

test "event struct size and alignment" {
    // 5*u64 + 4*u32 + 256 + 25*u64 reserved = 512 exactly: power-of-two
    // slots so the future mmap ring indexes with a shift.
    try std.testing.expectEqual(@as(usize, 512), @sizeOf(Event));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(Event));
}

test "opName covers all ops" {
    try std.testing.expectEqualStrings("CREATE", opName(1));
    try std.testing.expectEqualStrings("OVERFLOW", opName(7));
    try std.testing.expectEqualStrings("UNKNOWN", opName(999));
}
