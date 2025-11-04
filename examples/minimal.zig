const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const encoded = try base64UrlEncode(allocator, "Hello, world!");
    defer allocator.free(encoded);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Encoded: {s}\n", .{encoded});
    try stdout.flush();
}

fn base64UrlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const base64 = std.base64;
    const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(input.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);
    _ = base64.url_safe_no_pad.Encoder.encode(encoded, input);
    return encoded;
}
