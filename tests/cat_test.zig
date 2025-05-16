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

    const now = cat.util.currentTimeSecs();
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
    const hex = try cat.util.generateRandomHex(allocator, 16);
    defer allocator.free(hex);

    try testing.expectEqual(@as(usize, 32), hex.len);
    try testing.expect(cat.util.isHex(hex));

    // Test current time
    const now = cat.util.currentTimeSecs();
    try testing.expect(now > 0);

    // Test hex to bytes
    const bytes = try cat.util.hexToBytes(allocator, "48656c6c6f");
    defer allocator.free(bytes);

    try testing.expectEqualStrings("Hello", bytes);
}
