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

    const enable_dotnet = b.option(bool, "dotnet", "Enable .NET assembly support (default: true)") orelse true;

    // x86 target for 32-bit binaries
    const target_x86 = b.resolveTargetQuery(.{
        .os_tag = .windows,
        .abi = .gnu,
        .cpu_arch = .x86,
    });

    // Shared PE module (64-bit) so examples can @import("pe")
    const pe_module = b.createModule(.{
        .root_source_file = b.path("src/pe.zig"),
        .target = target,
        .optimize = optimize,
    });

    const src_inc = b.path("src");

    const options_module = b.addOptions();
    options_module.addOption(bool, "dotnet", enable_dotnet);
    pe_module.addImport("build_options", options_module.createModule());
    pe_module.addIncludePath(src_inc);

    // PE module (32-bit) for x86 examples
    const pe_module_x86 = b.createModule(.{
        .root_source_file = b.path("src/pe.zig"),
        .target = target_x86,
        .optimize = optimize,
    });

    const options_module_x86 = b.addOptions();
    options_module_x86.addOption(bool, "dotnet", enable_dotnet);
    pe_module_x86.addImport("build_options", options_module_x86.createModule());
    pe_module_x86.addIncludePath(src_inc);


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

    // putty32 executable (x86)
    const putty86 = b.addExecutable(.{
        .name = "zig-pe-putty32",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/examples/putty32_test.zig"),
            .target = target_x86,
            .optimize = optimize,
            .strip = true,
            .pic = true,
            .imports = &.{
                .{ .name = "pe", .module = pe_module_x86 },
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

    // Unit tests (pe.zig inline tests)
    const pe_test_module = b.createModule(.{
        .root_source_file = b.path("src/pe.zig"),
        .target = target,
        .optimize = optimize,
    });
    pe_test_module.addIncludePath(src_inc);

    const exe_unit_tests = b.addTest(.{
        .root_module = pe_test_module,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Unit tests (test.zig)
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "pe", .module = pe_module },
        },
    });
    test_module.addIncludePath(src_inc);

    const test_zig = b.addTest(.{
        .root_module = test_module,
    });

    const run_test_zig = b.addRunArtifact(test_zig);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
    test_step.dependOn(&run_test_zig.step);
}

fn configureExe(exe: *std.Build.Step.Compile) void {
    exe.root_module.link_libc = true;
    exe.lto = .full;
    exe.pie = true;
    exe.bundle_compiler_rt = true;
    exe.compress_debug_sections = .zstd;
    exe.link_data_sections = true;
}
