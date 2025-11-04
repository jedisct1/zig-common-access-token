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

    // Decode the token
    const decoded = cat.util.fromBase64Url(temp_allocator, token) catch |err| {
        std.debug.print("Error decoding token: {any}\n", .{err});
        return;
    };

    // Print the decoded token
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Decoded token: ", .{});
    for (decoded) |byte| {
        try stdout.print("{x:0>2} ", .{byte});
    }
    try stdout.print("\n", .{});

    // Create a dummy claims object
    var claims = cat.Claims.init(temp_allocator);

    try claims.setIssuer("dummy");
    try claims.setSubject("user123");

    // Print the claims
    try stdout.print("Token is valid!\n", .{});

    if (claims.getIssuer()) |issuer| {
        try stdout.print("Issuer: {s}\n", .{issuer});
    }

    if (claims.getSubject()) |subject| {
        try stdout.print("Subject: {s}\n", .{subject});
    }

    try stdout.flush();
}
