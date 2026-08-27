const std = @import("std");

const lmdb_files: []const []const u8 = &.{ "mdb.c", "midl.c" };

/// Vendored LMDB 1.0.0 (lib/lmdb, hash-verified against the databases/lmdb
/// port distinfo).  Static: brfsd must carry no runtime deps the rig
/// guests can't resolve (their pkg/DNS is broken by design).
fn addLmdb(b: *std.Build, mod: *std.Build.Module) void {
    mod.addIncludePath(b.path("lib/lmdb"));
    mod.addCSourceFiles(.{ .root = b.path("lib/lmdb"), .files = lmdb_files });
}

/// Link base-system OpenSSL for TLS/KTLS support.
/// The rig VMs have base-system libssl.so.35 (OpenSSL 3.5.x); the host
/// also has a ports-installed /usr/local/lib/libssl.so.12 which Zig's
/// default search order picks up first.  Use addObjectFile with the
/// explicit base-system .so to guarantee the correct library.
fn addOpenSsl(b: *std.Build, mod: *std.Build.Module) void {
    mod.addIncludePath(.{ .cwd_relative = "/usr/include" });
    mod.addObjectFile(b.path("lib/ssl-link/libssl.so"));
    mod.addObjectFile(b.path("lib/ssl-link/libcrypto.so"));
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ucl_mod = b.createModule(.{
        .root_source_file = b.path("lib/ucl/ucl.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ucl_mod.addIncludePath(.{ .cwd_relative = "/usr/include/private/ucl" });
    ucl_mod.linkSystemLibrary("privateucl", .{});

    const brfsd_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    brfsd_mod.addImport("ucl", ucl_mod);
    addLmdb(b, brfsd_mod);
    addOpenSsl(b, brfsd_mod);

    const brfsd = b.addExecutable(.{
        .name = "brfsd",
        .root_module = brfsd_mod,
    });
    b.installArtifact(brfsd);

    const ctl_proto_mod = b.createModule(.{
        .root_source_file = b.path("src/ctl.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const brfsctl_mod = b.createModule(.{
        .root_source_file = b.path("ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    brfsctl_mod.addImport("brfs_ctl", ctl_proto_mod);

    const brfsctl = b.addExecutable(.{
        .name = "brfsctl",
        .root_module = brfsctl_mod,
    });
    b.installArtifact(brfsctl);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport("ucl", ucl_mod);
    addLmdb(b, test_mod);
    addOpenSsl(b, test_mod);

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
