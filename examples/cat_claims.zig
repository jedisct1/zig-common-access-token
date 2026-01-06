const std = @import("std");
const Io = std.Io;
const cat = @import("cat");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

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

    var claims = cat.Claims.init(temp_allocator);

    try claims.setIssuer("eyevinn");
    try claims.setSubject("user123");
    try claims.setAudience("service");

    const now = cat.util.currentTimeSecs();
    try claims.setExpiration(now + 120);
    try claims.setIssuedAt(now);
    try claims.setCatVersion(1);

    var catr_map = std.AutoHashMap(u64, cat.ClaimValue).init(temp_allocator);
    try catr_map.put(0, cat.ClaimValue{ .Integer = 2 });
    try catr_map.put(4, cat.ClaimValue{ .String = "cta-common-access-token" });
    try catr_map.put(1, cat.ClaimValue{ .Integer = 120 });
    try catr_map.put(2, cat.ClaimValue{ .Integer = 60 });
    try claims.setClaim(cat.claims.LABEL_CATR, cat.ClaimValue{ .Map = catr_map });

    var catu_map = std.AutoHashMap(u64, cat.ClaimValue).init(temp_allocator);
    var scheme_map = std.AutoHashMap(u64, cat.ClaimValue).init(temp_allocator);
    try scheme_map.put(0, cat.ClaimValue{ .String = "https" });
    try catu_map.put(0, cat.ClaimValue{ .Map = scheme_map });
    try claims.setClaim(cat.claims.LABEL_CATU, cat.ClaimValue{ .Map = catu_map });

    const generate_options = cat.CatGenerateOptions{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    };

    const token = try cat_instance.generate(claims, generate_options);
    defer allocator.free(token);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Generated token with CAT-specific claims: {s}\n", .{token});
    try stdout.flush();
}
