const std = @import("std");

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

    const brfsd = b.addExecutable(.{
        .name = "brfsd",
        .root_module = brfsd_mod,
    });
    b.installArtifact(brfsd);

    const brfsctl_mod = b.createModule(.{
        .root_source_file = b.path("ctl/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

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

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
