const std = @import("std");

pub fn main() !void {
    // Initialize the allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a simple base64 encoded string
    const encoded = try base64UrlEncode(allocator, "Hello, world!");
    defer allocator.free(encoded);

    // Print the encoded string
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Encoded: {s}\n", .{encoded});
}

fn base64UrlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const base64 = std.base64;

    // Calculate the base64 encoded length
    const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(input.len);

    // Allocate memory for the encoded string
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);

    // Encode the data
    _ = base64.url_safe_no_pad.Encoder.encode(encoded, input);

    return encoded;
}
