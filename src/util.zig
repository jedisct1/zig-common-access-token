const std = @import("std");
const base64 = std.base64;
const time = std.time;
const crypto = std.crypto;
const testing = std.testing;

const Error = @import("error.zig").Error;

/// Encodes binary data to base64 URL-safe format without padding
pub fn toBase64NoPadding(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoded_len = base64.url_safe_no_pad.Encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);
    _ = base64.url_safe_no_pad.Encoder.encode(encoded, data);
    return encoded;
}

/// Decodes a base64 URL-safe string to binary data
pub fn fromBase64Url(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const max_decoded_len = base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch {
        return Error.Base64DecodingError;
    };

    const decoded = try allocator.alloc(u8, max_decoded_len);
    errdefer allocator.free(decoded);

    base64.url_safe_no_pad.Decoder.decode(decoded, encoded) catch {
        return Error.Base64DecodingError;
    };

    return decoded;
}

/// Generates a random hex string of specified length
pub fn generateRandomHex(allocator: std.mem.Allocator, bytes: usize) ![]u8 {
    const random_bytes = try allocator.alloc(u8, bytes);
    defer allocator.free(random_bytes);
    crypto.random.bytes(random_bytes);

    const hex_str = try allocator.alloc(u8, bytes * 2);
    for (random_bytes, 0..) |byte, i| {
        _ = try std.fmt.bufPrint(hex_str[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte});
    }
    return hex_str;
}

/// Returns the current time in seconds since the Unix epoch
pub fn currentTimeSecs() i64 {
    const ts = std.posix.clock_gettime(std.posix.CLOCK.REALTIME) catch unreachable;
    return @intCast(ts.sec);
}

/// Checks if a string is a valid hex string
pub fn isHex(str: []const u8) bool {
    for (str) |c| {
        const is_digit = c >= '0' and c <= '9';
        const is_lower_hex = c >= 'a' and c <= 'f';
        const is_upper_hex = c >= 'A' and c <= 'F';

        if (!is_digit and !is_lower_hex and !is_upper_hex) {
            return false;
        }
    }

    return true;
}

/// Converts a hex string to bytes
pub fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return Error.InvalidArgument;

    const bytes = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(bytes);
    _ = std.fmt.hexToBytes(bytes, hex) catch return Error.InvalidArgument;
    return bytes;
}

test "base64 encoding and decoding" {
    const test_data = "Hello, world!";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const encoded = try toBase64NoPadding(allocator, test_data);
    const decoded = try fromBase64Url(allocator, encoded);

    try testing.expectEqualStrings(test_data, decoded);
}

test "random hex generation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const hex = try generateRandomHex(allocator, 16);
    try testing.expectEqual(@as(usize, 32), hex.len);
    try testing.expect(isHex(hex));
}

test "current time" {
    const now = currentTimeSecs();
    try testing.expect(now > 0);
}

test "hex validation" {
    try testing.expect(isHex("0123456789abcdef"));
    try testing.expect(isHex("0123456789ABCDEF"));
    try testing.expect(!isHex("0123456789abcdefg"));
}

test "hex to bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const bytes = try hexToBytes(allocator, "48656c6c6f");
    try testing.expectEqualStrings("Hello", bytes);
}
