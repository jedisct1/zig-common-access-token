const std = @import("std");
const testing = std.testing;
const cat = @import("cat.zig");
const Claims = @import("claims.zig").Claims;
const util = @import("util.zig");

// Test creating and manipulating claims
test "cat - claims creation and manipulation" {
    const allocator = testing.allocator;

    // Create claims
    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Set claims
    try claims.setIssuer("issuer");
    try claims.setSubject("subject");
    try claims.setAudience("audience");
    try claims.setExpiration(1000);
    try claims.setNotBefore(500);
    try claims.setIssuedAt(500);
    try claims.setJwtId("jwt-id");

    // Verify claims
    try testing.expectEqualStrings("issuer", claims.getIssuer().?);
    try testing.expectEqualStrings("subject", claims.getSubject().?);
    try testing.expectEqualStrings("audience", claims.getAudience().?);
    try testing.expectEqual(@as(i64, 1000), claims.getExpiration().?);
    try testing.expectEqual(@as(i64, 500), claims.getNotBefore().?);
    try testing.expectEqual(@as(i64, 500), claims.getIssuedAt().?);
    try testing.expectEqualStrings("jwt-id", claims.getJwtId().?);
}

// Test serializing claims to CBOR
test "cat - claims serialization" {
    const allocator = testing.allocator;

    // Create claims
    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Set claims
    try claims.setIssuer("issuer");
    try claims.setSubject("subject");

    // Serialize to CBOR
    const cbor_data = try claims.toCbor(allocator);
    defer allocator.free(cbor_data);

    // Deserialize from CBOR
    var decoded_claims = try Claims.fromCbor(allocator, cbor_data);
    defer decoded_claims.deinit();

    // Verify claims
    try testing.expectEqualStrings("issuer", decoded_claims.getIssuer().?);
    try testing.expectEqualStrings("subject", decoded_claims.getSubject().?);
}

// Test token generation and validation
test "cat - token generation and validation" {
    const allocator = testing.allocator;

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try util.hexToBytes(allocator, key_hex);
    defer allocator.free(key);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(allocator);
    defer keys.deinit();
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
    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("issuer");
    try claims.setSubject("subject");
    try claims.setAudience("audience");

    const now = util.currentTimeSecs();
    try claims.setExpiration(now + 120); // 2 minutes from now
    try claims.setIssuedAt(now);

    // Create token generation options
    const generate_options = cat.CatGenerateOptions{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    };

    // Generate the token
    const token = try cat_instance.generate(claims, generate_options);
    defer allocator.free(token);

    // Create validation options
    const validation_options = cat.CatValidationOptions{
        .issuer = "issuer",
        .audience = "audience",
    };

    // Validate the token
    var validated_claims = try cat_instance.validate(token, cat.CatValidationType.Mac, validation_options);
    defer validated_claims.deinit();

    // Verify claims
    try testing.expectEqualStrings("issuer", validated_claims.getIssuer().?);
    try testing.expectEqualStrings("subject", validated_claims.getSubject().?);
    try testing.expectEqualStrings("audience", validated_claims.getAudience().?);
}

// Test token validation with invalid issuer
test "cat - token validation with invalid issuer" {
    const allocator = testing.allocator;

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try util.hexToBytes(allocator, key_hex);
    defer allocator.free(key);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(allocator);
    defer keys.deinit();
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
    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("issuer");
    try claims.setSubject("subject");
    try claims.setAudience("audience");

    const now = util.currentTimeSecs();
    try claims.setExpiration(now + 120); // 2 minutes from now
    try claims.setIssuedAt(now);

    // Create token generation options
    const generate_options = cat.CatGenerateOptions{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    };

    // Generate the token
    const token = try cat_instance.generate(claims, generate_options);
    defer allocator.free(token);

    // Create validation options with invalid issuer
    const validation_options = cat.CatValidationOptions{
        .issuer = "invalid-issuer",
        .audience = "audience",
    };

    // Validate the token (should fail)
    const result = cat_instance.validate(token, cat.CatValidationType.Mac, validation_options);
    try testing.expectError(cat.Error.InvalidIssuer, result);
}

// Test token validation with expired token
test "cat - token validation with expired token" {
    const allocator = testing.allocator;

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try util.hexToBytes(allocator, key_hex);
    defer allocator.free(key);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(allocator);
    defer keys.deinit();
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
    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("issuer");
    try claims.setSubject("subject");
    try claims.setAudience("audience");

    const now = util.currentTimeSecs();
    try claims.setExpiration(now - 120); // 2 minutes in the past (expired)
    try claims.setIssuedAt(now - 240);

    // Create token generation options
    const generate_options = cat.CatGenerateOptions{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    };

    // Generate the token
    const token = try cat_instance.generate(claims, generate_options);
    defer allocator.free(token);

    // Create validation options
    const validation_options = cat.CatValidationOptions{
        .issuer = "issuer",
        .audience = "audience",
    };

    // Validate the token (should fail)
    const result = cat_instance.validate(token, cat.CatValidationType.Mac, validation_options);
    try testing.expectError(cat.Error.TokenExpired, result);
}
