const std = @import("std");
const Io = std.Io;
const cat = @import("cat");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();

    const arg0 = args_iter.next() orelse "validate";
    const token = args_iter.next() orelse {
        std.debug.print("Usage: {s} <token>\n", .{arg0});
        return;
    };

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

    var claims = cat_instance.validate(token, cat.CatValidationType.Mac, .{
        .issuer = "example",
        .audience = null,
    }) catch |err| {
        std.debug.print("Error validating token: {any}\n", .{err});
        return;
    };
    defer claims.deinit();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
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
