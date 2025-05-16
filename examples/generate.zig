const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    // Initialize the allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a simple token
    const token = try cat.util.toBase64NoPadding(allocator, &[_]u8{0xA0});
    defer allocator.free(token);

    // Print the token
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Generated token: {s}\n", .{token});

    // Create claims
    var claims = cat.Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("eyevinn");
    try claims.setSubject("user123");

    // Print the claims
    if (claims.getIssuer()) |issuer| {
        try stdout.print("Issuer: {s}\n", .{issuer});
    }

    if (claims.getSubject()) |subject| {
        try stdout.print("Subject: {s}\n", .{subject});
    }
}
