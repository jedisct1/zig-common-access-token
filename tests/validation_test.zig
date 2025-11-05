const std = @import("std");
const testing = std.testing;
const cat = @import("zig-common-access-token");

const Claims = cat.Claims;
const ClaimValue = cat.ClaimValue;
const validation = cat.validation;

test "CATU validation - valid URL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATU claim: scheme=https, host suffix=.example.com
    var catu_map = std.AutoHashMap(u64, ClaimValue).init(allocator);

    // Scheme component (0) with exact match (0)
    var scheme_match = std.AutoHashMap(u64, ClaimValue).init(allocator);
    try scheme_match.put(0, ClaimValue{ .String = try allocator.dupe(u8, "https") });
    try catu_map.put(0, ClaimValue{ .Map = scheme_match });

    // Host component (1) with suffix match (2)
    var host_match = std.AutoHashMap(u64, ClaimValue).init(allocator);
    try host_match.put(2, ClaimValue{ .String = try allocator.dupe(u8, ".example.com") });
    try catu_map.put(1, ClaimValue{ .Map = host_match });

    try claims.setClaim(312, ClaimValue{ .Map = catu_map });

    // Test valid URL
    try validation.validateCatu(allocator, claims, "https://api.example.com/path");
}

test "CATU validation - invalid scheme" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATU claim: scheme=https
    var catu_map = std.AutoHashMap(u64, ClaimValue).init(allocator);

    var scheme_match = std.AutoHashMap(u64, ClaimValue).init(allocator);
    try scheme_match.put(0, ClaimValue{ .String = try allocator.dupe(u8, "https") });
    try catu_map.put(0, ClaimValue{ .Map = scheme_match });

    try claims.setClaim(312, ClaimValue{ .Map = catu_map });

    // Test invalid scheme
    try testing.expectError(error.InvalidUriClaim, validation.validateCatu(allocator, claims, "http://api.example.com/path"));
}

test "CATM validation - valid method" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATM claim: allow GET and POST
    var methods = std.ArrayList(ClaimValue){};
    try methods.append(allocator, ClaimValue{ .String = try allocator.dupe(u8, "GET") });
    try methods.append(allocator, ClaimValue{ .String = try allocator.dupe(u8, "POST") });

    try claims.setClaim(313, ClaimValue{ .Array = methods });

    // Test valid methods
    try validation.validateCatm(claims, "GET");
    try validation.validateCatm(claims, "post"); // Case insensitive
}

test "CATM validation - invalid method" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATM claim: allow GET and POST
    var methods = std.ArrayList(ClaimValue){};
    try methods.append(allocator, ClaimValue{ .String = try allocator.dupe(u8, "GET") });
    try methods.append(allocator, ClaimValue{ .String = try allocator.dupe(u8, "POST") });

    try claims.setClaim(313, ClaimValue{ .Array = methods });

    // Test invalid method
    try testing.expectError(error.InvalidMethodClaim, validation.validateCatm(claims, "DELETE"));
}

test "CATREPLAY validation - permitted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setClaim(308, ClaimValue{ .Integer = 0 });

    // Replay permitted - even if seen before
    try validation.validateCatreplay(claims, true);
    try validation.validateCatreplay(claims, false);
}

test "CATREPLAY validation - prohibited" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setClaim(308, ClaimValue{ .Integer = 1 });

    // Should fail if seen before
    try testing.expectError(error.TokenReplayProhibited, validation.validateCatreplay(claims, true));

    // Should pass if not seen before
    try validation.validateCatreplay(claims, false);
}

test "CATREPLAY validation - reuse detection" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setClaim(308, ClaimValue{ .Integer = 2 });

    // Reuse detection mode - validation passes but caller should track
    try validation.validateCatreplay(claims, true);
    try validation.validateCatreplay(claims, false);
}

test "CATTPRINT validation - valid fingerprint" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    const test_fingerprint_type = cat.FingerprintType.JA4;
    const test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create CATTPRINT claim using the new helper function
    try claims.setCatTPrint(test_fingerprint_type, test_fingerprint_value);

    // Test valid fingerprint
    try validation.validateCattprint(allocator, claims, test_fingerprint_type, test_fingerprint_value);
    // Test case insensitive (lowercase comparison)
    try validation.validateCattprint(allocator, claims, test_fingerprint_type, "T13D1516H2_8DAAF6152771_B186095E22B6");
}

test "CATTPRINT validation - invalid fingerprint type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    const test_fingerprint_type = cat.FingerprintType.JA4;
    const test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create CATTPRINT claim with JA4
    try claims.setCatTPrint(test_fingerprint_type, test_fingerprint_value);

    // Test with different fingerprint type (JA3) - should fail
    try testing.expectError(error.InvalidTlsFingerprintClaim, validation.validateCattprint(allocator, claims, cat.FingerprintType.JA3, test_fingerprint_value));
}

test "CATTPRINT validation - invalid fingerprint value" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    const test_fingerprint_type = cat.FingerprintType.JA4;
    const test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create CATTPRINT claim
    try claims.setCatTPrint(test_fingerprint_type, test_fingerprint_value);

    // Test with wrong fingerprint value - should fail
    const wrong_value = "t65a1516h2_8daaf6152771_b186095e22d3";
    try testing.expectError(error.InvalidTlsFingerprintClaim, validation.validateCattprint(allocator, claims, test_fingerprint_type, wrong_value));
}

test "CATTPRINT validation - no claim present" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // No CATTPRINT claim - should pass validation
    try validation.validateCattprint(allocator, claims, cat.FingerprintType.JA4, "t13d1516h2_8daaf6152771_b186095e22b6");
}

test "CATU validation - parent_path component" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATU claim: parent_path with exact match
    var catu_map = std.AutoHashMap(u64, ClaimValue).init(allocator);

    // Parent path component (5) with exact match (0)
    var parent_path_match = std.AutoHashMap(u64, ClaimValue).init(allocator);
    try parent_path_match.put(0, ClaimValue{ .String = try allocator.dupe(u8, "/videos/") });
    try catu_map.put(5, ClaimValue{ .Map = parent_path_match });

    try claims.setClaim(312, ClaimValue{ .Map = catu_map });

    // Test valid parent path
    try validation.validateCatu(allocator, claims, "https://example.com/videos/file.mp4");
}

test "CATU validation - filename component" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATU claim: filename with exact match
    var catu_map = std.AutoHashMap(u64, ClaimValue).init(allocator);

    // Filename component (6) with exact match (0)
    var filename_match = std.AutoHashMap(u64, ClaimValue).init(allocator);
    try filename_match.put(0, ClaimValue{ .String = try allocator.dupe(u8, "video.mp4") });
    try catu_map.put(6, ClaimValue{ .Map = filename_match });

    try claims.setClaim(312, ClaimValue{ .Map = catu_map });

    // Test valid filename
    try validation.validateCatu(allocator, claims, "https://example.com/path/video.mp4");
}

test "CATU validation - stem component" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    // Create CATU claim: stem with exact match
    var catu_map = std.AutoHashMap(u64, ClaimValue).init(allocator);

    // Stem component (7) with exact match (0)
    var stem_match = std.AutoHashMap(u64, ClaimValue).init(allocator);
    try stem_match.put(0, ClaimValue{ .String = try allocator.dupe(u8, "archive.tar") });
    try catu_map.put(7, ClaimValue{ .Map = stem_match });

    try claims.setClaim(312, ClaimValue{ .Map = catu_map });

    // Test valid stem (for archive.tar.gz, stem should be archive.tar)
    try validation.validateCatu(allocator, claims, "https://example.com/path/archive.tar.gz");
}
