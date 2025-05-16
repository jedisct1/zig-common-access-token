const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Create a module for the library
    const cat_module = b.addModule("cat", .{
        .root_source_file = b.path("src/main.zig"),
    });

    // Build the library
    const lib = b.addStaticLibrary(.{
        .name = "zig-cat",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Build examples
    const generate_example = b.addExecutable(.{
        .name = "generate",
        .root_source_file = b.path("examples/generate.zig"),
        .target = target,
        .optimize = optimize,
    });
    generate_example.root_module.addImport("cat", cat_module);
    b.installArtifact(generate_example);

    const validate_example = b.addExecutable(.{
        .name = "validate",
        .root_source_file = b.path("examples/validate.zig"),
        .target = target,
        .optimize = optimize,
    });
    validate_example.root_module.addImport("cat", cat_module);
    b.installArtifact(validate_example);

    const interop_example = b.addExecutable(.{
        .name = "interop",
        .root_source_file = b.path("examples/interop.zig"),
        .target = target,
        .optimize = optimize,
    });
    interop_example.root_module.addImport("cat", cat_module);
    b.installArtifact(interop_example);

    const cat_claims_example = b.addExecutable(.{
        .name = "cat_claims",
        .root_source_file = b.path("examples/cat_claims.zig"),
        .target = target,
        .optimize = optimize,
    });
    cat_claims_example.root_module.addImport("cat", cat_module);
    b.installArtifact(cat_claims_example);

    const minimal_example = b.addExecutable(.{
        .name = "minimal",
        .root_source_file = b.path("examples/minimal.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(minimal_example);

    // Build tests
    const tests = b.addTest(.{
        .root_source_file = b.path("tests/cat_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.root_module.addImport("cat", cat_module);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);

    // Run examples
    const run_generate = b.addRunArtifact(generate_example);
    const generate_step = b.step("generate", "Run the generate example");
    generate_step.dependOn(&run_generate.step);

    const run_validate = b.addRunArtifact(validate_example);
    if (b.args) |args| {
        run_validate.addArgs(args);
    }
    const validate_step = b.step("validate", "Run the validate example");
    validate_step.dependOn(&run_validate.step);

    const run_interop = b.addRunArtifact(interop_example);
    if (b.args) |args| {
        run_interop.addArgs(args);
    }
    const interop_step = b.step("interop", "Run the interop example");
    interop_step.dependOn(&run_interop.step);

    const run_cat_claims = b.addRunArtifact(cat_claims_example);
    const cat_claims_step = b.step("cat_claims", "Run the cat_claims example");
    cat_claims_step.dependOn(&run_cat_claims.step);

    const run_minimal = b.addRunArtifact(minimal_example);
    const minimal_step = b.step("minimal", "Run the minimal example");
    minimal_step.dependOn(&run_minimal.step);
}
