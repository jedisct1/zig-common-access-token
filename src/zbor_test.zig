const std = @import("std");
const testing = std.testing;
const zbor = @import("zbor.zig");

// Test encoding and decoding unsigned integers
test "zbor - unsigned integers" {
    const allocator = testing.allocator;

    // Test values
    const values = [_]u64{ 0, 1, 10, 23, 24, 25, 100, 1000, 1000000, 1000000000, 1000000000000 };

    for (values) |value| {
        // Encode
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.pushInt(value);

        const encoded = try encoder.finish();
        defer allocator.free(encoded);

        // Decode
        var decoder = zbor.Decoder.init(encoded, allocator);
        defer decoder.deinit();

        const decoded = try decoder.readInt(u64);

        // Verify
        try testing.expectEqual(value, decoded);
    }
}

// Test encoding and decoding negative integers
test "zbor - negative integers" {
    const allocator = testing.allocator;

    // Test values
    const values = [_]i64{ -1, -10, -100, -1000, -1000000, -1000000000, -1000000000000 };

    for (values) |value| {
        // Encode
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.pushInt(value);

        const encoded = try encoder.finish();
        defer allocator.free(encoded);

        // Decode
        var decoder = zbor.Decoder.init(encoded, allocator);
        defer decoder.deinit();

        const decoded = try decoder.readInt(i64);

        // Verify
        try testing.expectEqual(value, decoded);
    }
}

// Test encoding and decoding byte strings
test "zbor - byte strings" {
    const allocator = testing.allocator;

    // Test values
    const values = [_][]const u8{
        "",
        "a",
        "hello",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    };

    for (values) |value| {
        // Encode
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.pushBytes(value);

        const encoded = try encoder.finish();
        defer allocator.free(encoded);

        // Decode
        var decoder = zbor.Decoder.init(encoded, allocator);
        defer decoder.deinit();

        const decoded = try decoder.readBytes(allocator);
        defer allocator.free(decoded);

        // Verify
        try testing.expectEqualSlices(u8, value, decoded);
    }
}

// Test encoding and decoding text strings
test "zbor - text strings" {
    const allocator = testing.allocator;

    // Test values
    const values = [_][]const u8{
        "",
        "a",
        "hello",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "Unicode: ñáéíóú 你好 😀",
    };

    for (values) |value| {
        // Encode
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.pushText(value);

        const encoded = try encoder.finish();
        defer allocator.free(encoded);

        // Decode
        var decoder = zbor.Decoder.init(encoded, allocator);
        defer decoder.deinit();

        const decoded = try decoder.readText(allocator);
        defer allocator.free(decoded);

        // Verify
        try testing.expectEqualSlices(u8, value, decoded);
    }
}

// Test encoding and decoding arrays
test "zbor - arrays" {
    const allocator = testing.allocator;

    // Encode an array of integers
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.beginArray(3);
    try encoder.pushInt(1);
    try encoder.pushInt(2);
    try encoder.pushInt(3);
    try encoder.endArray();

    const encoded = try encoder.finish();
    defer allocator.free(encoded);

    // Decode
    var decoder = zbor.Decoder.init(encoded, allocator);
    defer decoder.deinit();

    const array_len = try decoder.beginArray();
    try testing.expectEqual(@as(usize, 3), array_len);

    try testing.expectEqual(@as(i64, 1), try decoder.readInt(i64));
    try testing.expectEqual(@as(i64, 2), try decoder.readInt(i64));
    try testing.expectEqual(@as(i64, 3), try decoder.readInt(i64));

    try decoder.endArray();
}

// Test encoding and decoding maps
test "zbor - maps" {
    const allocator = testing.allocator;

    // Encode a map
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.beginMap(2);
    try encoder.pushInt(1);
    try encoder.pushText("one");
    try encoder.pushInt(2);
    try encoder.pushText("two");
    try encoder.endMap();

    const encoded = try encoder.finish();
    defer allocator.free(encoded);

    // Decode
    var decoder = zbor.Decoder.init(encoded, allocator);
    defer decoder.deinit();

    const map_len = try decoder.beginMap();
    try testing.expectEqual(@as(usize, 2), map_len);

    const key1 = try decoder.readInt(i64);
    const value1 = try decoder.readText(allocator);
    defer allocator.free(value1);

    const key2 = try decoder.readInt(i64);
    const value2 = try decoder.readText(allocator);
    defer allocator.free(value2);

    try decoder.endMap();

    // Verify
    try testing.expectEqual(@as(i64, 1), key1);
    try testing.expectEqualSlices(u8, "one", value1);
    try testing.expectEqual(@as(i64, 2), key2);
    try testing.expectEqualSlices(u8, "two", value2);
}

// Test encoding and decoding tags
test "zbor - tags" {
    const allocator = testing.allocator;

    // Encode a tagged value
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.pushTag(1);
    try encoder.pushText("2023-01-01T00:00:00Z");

    const encoded = try encoder.finish();
    defer allocator.free(encoded);

    // Decode
    var decoder = zbor.Decoder.init(encoded, allocator);
    defer decoder.deinit();

    const tag = try decoder.readTag();
    const value = try decoder.readText(allocator);
    defer allocator.free(value);

    // Verify
    try testing.expectEqual(@as(u64, 1), tag);
    try testing.expectEqualSlices(u8, "2023-01-01T00:00:00Z", value);
}

// Test encoding and decoding boolean values
test "zbor - boolean values" {
    const allocator = testing.allocator;

    // Test values
    const values = [_]bool{ true, false };

    for (values) |value| {
        // Encode
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.pushBool(value);

        const encoded = try encoder.finish();
        defer allocator.free(encoded);

        // Decode
        var decoder = zbor.Decoder.init(encoded, allocator);
        defer decoder.deinit();

        const decoded = try decoder.readBool();

        // Verify
        try testing.expectEqual(value, decoded);
    }
}

// Test encoding and decoding null values
test "zbor - null values" {
    const allocator = testing.allocator;

    // Encode
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.pushNull();

    const encoded = try encoder.finish();
    defer allocator.free(encoded);

    // Decode
    var decoder = zbor.Decoder.init(encoded, allocator);
    defer decoder.deinit();

    try decoder.readNull();
}

// Test encoding and decoding floating-point values
test "zbor - floating-point values" {
    const allocator = testing.allocator;

    // Test values
    const values = [_]f64{ 0.0, 1.0, -1.0, 3.14159, -3.14159, 1.0e10, -1.0e10 };

    for (values) |value| {
        // Encode
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.pushFloat(value);

        const encoded = try encoder.finish();
        defer allocator.free(encoded);

        // Decode
        var decoder = zbor.Decoder.init(encoded, allocator);
        defer decoder.deinit();

        const decoded = try decoder.readFloat(f64);

        // Verify (with epsilon for floating-point comparison)
        try testing.expectApproxEqAbs(value, decoded, 1e-10);
    }
}

// Test indefinite-length arrays
test "zbor - indefinite-length arrays" {
    const allocator = testing.allocator;

    // Encode an indefinite-length array
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.beginArrayIndefinite();
    try encoder.pushInt(1);
    try encoder.pushInt(2);
    try encoder.pushInt(3);
    try encoder.endArray();

    const encoded = try encoder.finish();
    defer allocator.free(encoded);

    // Decode
    var decoder = zbor.Decoder.init(encoded, allocator);
    defer decoder.deinit();

    try decoder.beginArrayIndefinite();

    try testing.expectEqual(@as(i64, 1), try decoder.readInt(i64));
    try testing.expectEqual(@as(i64, 2), try decoder.readInt(i64));
    try testing.expectEqual(@as(i64, 3), try decoder.readInt(i64));

    try decoder.endArray();
}
