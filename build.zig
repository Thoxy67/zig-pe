const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .os_tag = .windows,
            .abi = .gnu,
            // .cpu_arch = .x86,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    // Shared PE module so examples can @import("pe")
    const pe_module = b.createModule(.{
        .root_source_file = b.path("src/pe.zig"),
        .target = target,
        .optimize = optimize,
    });

    // putty64 executable
    const putty64 = b.addExecutable(.{
        .name = "zig-pe-putty64",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples/putty64_test.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .pic = true,
            .imports = &.{
                .{ .name = "pe", .module = pe_module },
            },
        }),
    });

    configureExe(putty64);
    putty64.subsystem = .Windows;

    b.installArtifact(putty64);

    const run_cmd = b.addRunArtifact(putty64);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run-putty64", "Run the putty64 app");
    run_step.dependOn(&run_cmd.step);

    // putty32 executable
    const putty86 = b.addExecutable(.{
        .name = "zig-pe-putty32",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples/putty32_test.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .pic = true,
            .imports = &.{
                .{ .name = "pe", .module = pe_module },
            },
        }),
    });

    configureExe(putty86);
    putty86.subsystem = .Windows;

    b.installArtifact(putty86);

    const run_putty32_cmd = b.addRunArtifact(putty86);
    run_putty32_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_putty32_cmd.addArgs(args);
    }

    const run_putty32_step = b.step("run-putty32", "Run the putty32 app");
    run_putty32_step.dependOn(&run_putty32_cmd.step);

    // .NET test executable
    const dotnet_exe = b.addExecutable(.{
        .name = "zig-pe-dotnet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples/dotnet_test.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .pic = true,
            .imports = &.{
                .{ .name = "pe", .module = pe_module },
            },
        }),
    });

    configureExe(dotnet_exe);

    b.installArtifact(dotnet_exe);

    const run_dotnet_cmd = b.addRunArtifact(dotnet_exe);
    run_dotnet_cmd.step.dependOn(b.getInstallStep());

    const run_dotnet_step = b.step("run-dotnet", "Run the .NET test");
    run_dotnet_step.dependOn(&run_dotnet_cmd.step);

    // Unit tests
    const exe_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/pe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}

fn configureExe(exe: *std.Build.Step.Compile) void {
    exe.root_module.link_libc = true;
    exe.lto = .full;
    exe.pie = true;
    exe.bundle_compiler_rt = true;
    exe.compress_debug_sections = .zstd;
    exe.link_data_sections = true;
}
