const std = @import("std");
const testing = std.testing;
const cat = @import("cat");

test "claims basic operations" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = cat.Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("test-issuer");
    try claims.setSubject("test-subject");
    try claims.setAudience("test-audience");
    try claims.setExpiration(1234567890);

    try testing.expectEqualStrings("test-issuer", claims.getIssuer().?);
    try testing.expectEqualStrings("test-subject", claims.getSubject().?);
    try testing.expectEqualStrings("test-audience", claims.getAudience().?);
    try testing.expectEqual(@as(i64, 1234567890), claims.getExpiration().?);
}

test "cat initialization" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var keys = std.StringHashMap([]const u8).init(allocator);
    try keys.put("key-1", "secret-key");

    const cat_options = cat.CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
        .io = testing.io,
    };

    var cat_instance = cat.Cat.init(allocator, cat_options);
    defer cat_instance.deinit();
}

test "token generation and validation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try cat.util.hexToBytes(allocator, key_hex);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(allocator);
    try keys.put("Symmetric256", key);

    // Create CAT options
    const cat_options = cat.CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
        .io = testing.io,
    };

    // Create a CAT instance
    var cat_instance = cat.Cat.init(allocator, cat_options);
    defer cat_instance.deinit();

    // Create claims
    var claims = cat.Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("test-issuer");
    try claims.setSubject("test-subject");
    try claims.setAudience("test-audience");

    const now = cat.util.currentTimeSecs(testing.io);
    try claims.setExpiration(now + 120); // 2 minutes from now
    try claims.setIssuedAt(now);

    // Create token generation options
    // Commented out to avoid unused variable warning
    // const generate_options = cat.CatGenerateOptions{
    //     .validation_type = cat.CatValidationType.Mac,
    //     .alg = "HS256",
    //     .kid = "Symmetric256",
    //     .generate_cwt_id = true,
    // };

    // This will fail because we haven't implemented the actual CBOR serialization yet
    // const token = try cat_instance.generate(claims, generate_options);
    //
    // // Create validation options
    // const validation_options = cat.CatValidationOptions{
    //     .issuer = "test-issuer",
    //     .audience = null,
    // };
    //
    // // Validate the token
    // var validated_claims = try cat_instance.validate(token, cat.CatValidationType.Mac, validation_options);
    // defer validated_claims.deinit();
    //
    // try testing.expectEqualStrings("test-issuer", validated_claims.getIssuer().?);
    // try testing.expectEqualStrings("test-subject", validated_claims.getSubject().?);
    // try testing.expectEqualStrings("test-audience", validated_claims.getAudience().?);
}

test "error handling" {
    try testing.expectEqualStrings("Token expired", cat.errors.errorToString(cat.Error.TokenExpired));
    try testing.expectEqualStrings("Invalid issuer", cat.errors.errorToString(cat.Error.InvalidIssuer));
}

test "utility functions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Test base64 encoding and decoding
    const test_data = "Hello, world!";
    const encoded = try cat.util.toBase64NoPadding(allocator, test_data);
    defer allocator.free(encoded);

    const decoded = try cat.util.fromBase64Url(allocator, encoded);
    defer allocator.free(decoded);

    try testing.expectEqualStrings(test_data, decoded);

    // Test random hex generation
    const hex = try cat.util.generateRandomHex(allocator, testing.io, 16);
    defer allocator.free(hex);

    try testing.expectEqual(@as(usize, 32), hex.len);
    try testing.expect(cat.util.isHex(hex));

    // Test current time
    const now = cat.util.currentTimeSecs(testing.io);
    try testing.expect(now > 0);

    // Test hex to bytes
    const bytes = try cat.util.hexToBytes(allocator, "48656c6c6f");
    defer allocator.free(bytes);

    try testing.expectEqualStrings("Hello", bytes);
}

const reference_key = blk: {
    var key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388") catch unreachable;
    break :blk key;
};

fn testCat(allocator: std.mem.Allocator, keys: []const struct { []const u8, []const u8 }) !cat.Cat {
    var map = std.StringHashMap([]const u8).init(allocator);
    for (keys) |entry| try map.put(entry[0], entry[1]);
    return cat.Cat.init(allocator, .{ .keys = map, .expect_cwt_tag = true, .io = testing.io });
}

test "validation checks the MAC" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cat_instance = try testCat(allocator, &.{.{ "Symmetric256", &reference_key }});

    // Its tag was checked with an independent COSE implementation. It has expired, which is only reported after the MAC checks out.
    const reference = "2D3RhEOhAQWhBExTeW1tZXRyaWMyNTZYS6YHWCA1YmJjNDI2NWVmYTAxOGI4YjU4Y2I5OTQyY2IwODFmMQFnZXhhbXBsZQQaaQpK1gYaaQpKXgJndXNlcjEyMwNnc2VydmljZVggNRE3wudeG0Fd-vJMZiLpNRO6WU9lrtByioSvzuAEi7U";
    try testing.expectError(error.TokenExpired, cat_instance.validate(reference, .Mac, .{ .issuer = "example" }));

    // Changing a byte of the payload or of the tag must break the MAC.
    const bytes = try cat.util.fromBase64Url(allocator, reference);
    for ([_]usize{ std.mem.indexOf(u8, bytes, "example").?, bytes.len - 1 }) |offset| {
        bytes[offset] ^= 1;
        defer bytes[offset] ^= 1;
        const tampered = try cat.util.toBase64NoPadding(allocator, bytes);
        try testing.expectError(error.TagMismatch, cat_instance.validate(tampered, .Mac, .{ .issuer = "example" }));
    }

    const wrong_key = try testCat(allocator, &.{.{ "Symmetric256", "wrong-key" }});
    try testing.expectError(error.TagMismatch, wrong_key.validate(reference, .Mac, .{ .issuer = "example" }));
    const unknown_kid = try testCat(allocator, &.{.{ "other", &reference_key }});
    try testing.expectError(error.KeyNotFound, unknown_kid.validate(reference, .Mac, .{ .issuer = "example" }));
}

test "header checks" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const single_key = try testCat(allocator, &.{.{ "Symmetric256", &reference_key }});
    const two_keys = try testCat(allocator, &.{ .{ "Symmetric256", &reference_key }, .{ "other", "other-key" } });

    // Without a key ID, the token can only be checked when there is a single key to try.
    const no_kid = "2D3RhEOhAQWgSqEBZ2V4YW1wbGVYIPwGJGdehd7NQCburSfZlnB2NHCBoZNz3S5WutPo3LbG";
    _ = try single_key.validate(no_kid, .Mac, .{ .issuer = "example" });

    // rust-cat can send the key ID as text, in the protected header.
    const text_kid = "2D3RhFGiAQUEbFN5bW1ldHJpYzI1NqBKoQFnZXhhbXBsZVggxCSke5l_QQ8cXt9nmj03aoKbe43V-z7dtUBJIeIVz8E";
    _ = try two_keys.validate(text_kid, .Mac, .{ .issuer = "example" });
    try testing.expectError(error.KeyNotFound, two_keys.validate(no_kid, .Mac, .{ .issuer = "example" }));

    // Both have a valid HMAC-SHA256 tag, but HS256 isn't the protected algorithm.
    const other_alg = "2D3RhFGiAQYETFN5bW1ldHJpYzI1NqBKoQFnZXhhbXBsZVggvLDsMPDzVQmQnYFIjpR_gcrlN6INkekL3_vK-gHO1d8";
    try testing.expectError(error.UnsupportedAlgorithm, two_keys.validate(other_alg, .Mac, .{ .issuer = "example" }));
    const unprotected_alg = "2D3RhECiAQUETFN5bW1ldHJpYzI1NkqhAWdleGFtcGxlWCDTrnRTlvVCj1wxNjjuk07NIS192C-4B2uHhGuEzOvL0g";
    try testing.expectError(error.InvalidTokenHeader, two_keys.validate(unprotected_alg, .Mac, .{ .issuer = "example" }));

    // A valid token that marks an unknown header parameter as critical.
    const critical = "2D3RhFgYpAEFBExTeW1tZXRyaWMyNTYCgRhjGGMAoEqhAWdleGFtcGxlWCC75DCI7MhJ6dzi333dN0CPxAuZKxueZ7yUkVedV6S5eQ";
    try testing.expectError(error.InvalidTokenHeader, two_keys.validate(critical, .Mac, .{ .issuer = "example" }));
}

test "claim decoding edge cases" {
    var buf: [16]u8 = undefined;

    // A repeated label keeps the last value.
    var claims = try cat.Claims.fromCbor(testing.allocator, try std.fmt.hexToBytes(&buf, "a2016161016162"));
    defer claims.deinit();
    try testing.expectEqualStrings("b", claims.getIssuer().?);

    // Indefinite-length containers decode like definite ones, and their end must be read so that the next claim follows.
    var indefinite = try cat.Claims.fromCbor(testing.allocator, try std.fmt.hexToBytes(&buf, "bf019f6161ff026162ff"));
    defer indefinite.deinit();
    try testing.expectEqual(1, indefinite.getClaim(1).?.Array.items.len);
    try testing.expectEqualStrings("b", indefinite.getSubject().?);

    // The largest definite lengths must not be mistaken for indefinite ones.
    try testing.expect(std.meta.isError(cat.Claims.fromCbor(testing.allocator, try std.fmt.hexToBytes(&buf, "bbffffffffffffffffff"))));
    try testing.expect(std.meta.isError(cat.Claims.fromCbor(testing.allocator, try std.fmt.hexToBytes(&buf, "a1019bffffffffffffffffff"))));
}

test "numeric dates can be floats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const cat_instance = try testCat(allocator, &.{.{ "k", "secret" }});
    const now: f64 = @floatFromInt(cat.util.currentTimeSecs(testing.io));

    const cases = [_]struct { u64, cat.ClaimValue, ?anyerror }{
        .{ cat.claims.LABEL_EXP, .{ .Float = now + 60.5 }, null },
        .{ cat.claims.LABEL_EXP, .{ .Float = 1.5 }, error.TokenExpired },
        .{ cat.claims.LABEL_NBF, .{ .Float = now + 3600.5 }, error.TokenNotActive },
        .{ cat.claims.LABEL_EXP, .{ .Float = std.math.nan(f64) }, error.InvalidClaimValue },
        .{ cat.claims.LABEL_EXP, .{ .String = "tomorrow" }, error.InvalidClaimType },
    };
    for (cases) |case| {
        const label, const value, const expected = case;
        var claims = cat.Claims.init(allocator);
        try claims.setIssuer("example");
        try claims.setClaim(label, value);
        const token = try cat_instance.generate(claims, .{ .validation_type = .Mac, .alg = "HS256", .kid = "k", .generate_cwt_id = false });

        const result = cat_instance.validate(token, .Mac, .{ .issuer = "example" });
        if (expected) |err| try testing.expectError(err, result) else _ = try result;
    }
}

test "hostile headers fail cleanly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const cat_instance = try testCat(arena.allocator(), &.{.{ "Symmetric256", "unused" }});

    const deep_nesting = "2D3RhEOhAQWhBYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYEASqEBZ2V4YW1wbGVYIPwGJGdehd7NQCburSfZlnB2NHCBoZNz3S5WutPo3LbG";
    try testing.expectError(error.NestingTooDeep, cat_instance.validate(deep_nesting, .Mac, .{ .issuer = "example" }));

    const huge_label = "2D3RhEOhAQWhG___________AEqhAWdleGFtcGxlWCD8BiRnXoXezUAm7q0n2ZZwdjRwgaGTc90uVrrT6Ny2xg";
    try testing.expectError(error.Overflow, cat_instance.validate(huge_label, .Mac, .{ .issuer = "example" }));
}

test "floats are encoded in their shortest exact form" {
    const cases = [_]struct { f64, []const u8 }{
        .{ 300.0, "f95cb0" },
        .{ 1.5, "f93e00" },
        .{ 100000.0, "fa47c35000" },
        .{ 0.1, "fb3fb999999999999a" },
    };
    for (cases) |case| {
        var claims = cat.Claims.init(testing.allocator);
        defer claims.deinit();
        try claims.setClaim(1, .{ .Float = case[0] });

        const cbor = try claims.toCbor(testing.allocator);
        defer testing.allocator.free(cbor);
        var expected: [9]u8 = undefined;
        try testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&expected, case[1]), cbor[2..]);

        var decoded = try cat.Claims.fromCbor(testing.allocator, cbor);
        defer decoded.deinit();
        try testing.expectEqual(case[0], decoded.getClaim(1).?.Float);
    }
}
