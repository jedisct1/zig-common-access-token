const std = @import("std");
const Io = std.Io;
const cat = @import("cat");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try cat.util.hexToBytes(temp_allocator, key_hex);

    var keys = std.StringHashMap([]const u8).init(temp_allocator);
    try keys.put("Symmetric256", key);

    const cat_options = cat.CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
    };

    var cat_instance = cat.Cat.init(allocator, cat_options);
    defer cat_instance.deinit();

    var claims = cat.Claims.init(temp_allocator);

    try claims.setIssuer("example");
    try claims.setSubject("user123");
    try claims.setAudience("service");

    const now = cat.util.currentTimeSecs();
    try claims.setExpiration(now + 120);
    try claims.setIssuedAt(now);

    const token = try cat_instance.generate(claims, .{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    });
    defer allocator.free(token);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Generated token: {s}\n", .{token});
    try stdout.flush();
}
