const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    // Initialize the allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use arena allocator for temporary allocations
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try cat.util.hexToBytes(temp_allocator, key_hex);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(temp_allocator);
    try keys.put("Symmetric256", key);

    // Create CAT options
    const cat_options = cat.CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
    };

    // Create a CAT instance
    var cat_instance = cat.Cat.init(allocator, cat_options);
    defer cat_instance.deinit();

    // Create claims
    var claims = cat.Claims.init(temp_allocator);

    try claims.setIssuer("example");
    try claims.setSubject("user123");
    try claims.setAudience("service");

    const now = cat.util.currentTimeSecs();
    try claims.setExpiration(now + 120); // 2 minutes from now
    try claims.setIssuedAt(now);

    // Generate token
    const token = try cat_instance.generate(claims, .{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    });
    defer allocator.free(token);

    // Print the token
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Generated token: {s}\n", .{token});
    try stdout.flush();
}
