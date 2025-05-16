const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    // Initialize the allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try cat.util.hexToBytes(allocator, key_hex);
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
    var claims = cat.Claims.init(allocator);
    defer claims.deinit();

    // Set standard claims
    try claims.setIssuer("eyevinn");
    try claims.setSubject("user123");
    try claims.setAudience("service");

    const now = cat.util.currentTimeSecs();
    try claims.setExpiration(now + 120); // 2 minutes from now
    try claims.setIssuedAt(now);

    // Set CAT version
    try claims.setCatVersion(1);

    // Create a CATR (renewal) claim
    var catr_map = std.AutoHashMap(u64, cat.ClaimValue).init(allocator);
    defer {
        var it = catr_map.iterator();
        while (it.next()) |entry| {
            var value = entry.value_ptr.*;
            value.deinit();
        }
        catr_map.deinit();
    }

    // Type: header
    try catr_map.put(0, cat.ClaimValue{ .Integer = 2 }); // 2 = header

    // Header name
    try catr_map.put(4, cat.ClaimValue{ .String = "cta-common-access-token" });

    // Expiration add
    try catr_map.put(1, cat.ClaimValue{ .Integer = 120 });

    // Deadline
    try catr_map.put(2, cat.ClaimValue{ .Integer = 60 });

    // Add the CATR claim to the claims
    try claims.setClaim(cat.claims.LABEL_CATR, cat.ClaimValue{ .Map = catr_map });

    // Create a CATU (URI) claim
    var catu_map = std.AutoHashMap(u64, cat.ClaimValue).init(allocator);
    defer {
        var it = catu_map.iterator();
        while (it.next()) |entry| {
            var value = entry.value_ptr.*;
            value.deinit();
        }
        catu_map.deinit();
    }

    // Scheme
    var scheme_map = std.AutoHashMap(u64, cat.ClaimValue).init(allocator);
    try scheme_map.put(0, cat.ClaimValue{ .String = "https" }); // exact-match: https
    try catu_map.put(0, cat.ClaimValue{ .Map = scheme_map });

    // Add the CATU claim to the claims
    try claims.setClaim(cat.claims.LABEL_CATU, cat.ClaimValue{ .Map = catu_map });

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

    // Print the token
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Generated token with CAT-specific claims: {s}\n", .{token});
}
