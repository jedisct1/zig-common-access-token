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

    // Create a simple token
    const token = try cat.util.toBase64NoPadding(temp_allocator, &[_]u8{0xA0});

    // Print the token
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Generated token: {s}\n", .{token});

    // Create claims
    var claims = cat.Claims.init(temp_allocator);

    try claims.setIssuer("eyevinn");
    try claims.setSubject("user123");

    // Print the claims
    if (claims.getIssuer()) |issuer| {
        try stdout.print("Issuer: {s}\n", .{issuer});
    }

    if (claims.getSubject()) |subject| {
        try stdout.print("Subject: {s}\n", .{subject});
    }

    try stdout.flush();
}
