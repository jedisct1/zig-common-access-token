const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    // Check if a token was provided
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <token>\n", .{args[0]});
        return;
    }

    const token = args[1];

    // Initialize the allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use arena allocator for temporary allocations
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    // Create a key for token validation
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

    // Validate the token
    var claims = cat_instance.validate(token, cat.CatValidationType.Mac, .{
        .issuer = "example",
        .audience = null,
    }) catch |err| {
        std.debug.print("Error validating token: {any}\n", .{err});
        return;
    };
    defer claims.deinit();

    // Print the results
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Token is valid!\n", .{});

    if (claims.getIssuer()) |issuer| {
        try stdout.print("Issuer: {s}\n", .{issuer});
    }

    if (claims.getSubject()) |subject| {
        try stdout.print("Subject: {s}\n", .{subject});
    }

    if (claims.getAudience()) |audience| {
        try stdout.print("Audience: {s}\n", .{audience});
    }

    if (claims.getExpiration()) |exp| {
        try stdout.print("Expiration: {d}\n", .{exp});
    }

    try stdout.flush();
}
