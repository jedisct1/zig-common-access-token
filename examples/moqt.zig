const std = @import("std");
const Io = std.Io;
const cat = @import("cat");
const moqt = cat.moqt;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temp_allocator = arena.allocator();

    const key = try cat.util.hexToBytes(temp_allocator, "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388");
    var keys = std.StringHashMap([]const u8).init(temp_allocator);
    try keys.put("Symmetric256", key);

    var cat_instance = cat.Cat.init(allocator, .{ .keys = keys, .expect_cwt_tag = true, .io = io });
    defer cat_instance.deinit();

    // The issuer lets Alice connect and publish video tracks under example.com/alice.
    var claims = cat.Claims.init(temp_allocator);
    try claims.setIssuer("issuer.example.com");
    try claims.setExpiration(cat.util.currentTimeSecs(io) + 3600);
    try claims.setMoqt(&.{.{
        .actions = &.{ .ClientSetup, .PublishNamespace, .Publish },
        .namespace = &.{ .{ .Exact = "example.com" }, .{ .Exact = "alice" } },
        .track = .{ .Prefix = "video-" },
    }});
    // Relays must check that the token is still valid every 5 minutes while she publishes.
    try claims.setMoqtReval(300);

    const token = try cat_instance.generate(claims, .{
        .validation_type = .Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    });
    defer allocator.free(token);

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("MoQT token: {s}\n\n", .{token});

    // The relay checks every request against the token. It can revalidate tokens once a minute at most.
    const requests = [_]struct { []const u8, moqt.Request }{
        .{ "CLIENT_SETUP", .{ .action = .ClientSetup } },
        .{ "PUBLISH_NAMESPACE example.com/alice", .{ .action = .PublishNamespace, .namespace = &.{ "example.com", "alice" } } },
        .{ "PUBLISH example.com/alice video-hd", .{ .action = .Publish, .namespace = &.{ "example.com", "alice" }, .track = "video-hd" } },
        .{ "PUBLISH example.com/alice audio", .{ .action = .Publish, .namespace = &.{ "example.com", "alice" }, .track = "audio" } },
        .{ "PUBLISH example.com/bob video-hd", .{ .action = .Publish, .namespace = &.{ "example.com", "bob" }, .track = "video-hd" } },
        .{ "SUBSCRIBE example.com/alice video-hd", .{ .action = .Subscribe, .namespace = &.{ "example.com", "alice" }, .track = "video-hd" } },
    };
    for (requests) |entry| {
        const description, const request = entry;
        var validated = cat_instance.validate(token, .Mac, .{
            .issuer = "issuer.example.com",
            .moqt_request = request,
            .moqt_min_reval_interval = 60,
        }) catch |err| {
            try stdout.print("{s}: denied ({s})\n", .{ description, @errorName(err) });
            continue;
        };
        validated.deinit();
        try stdout.print("{s}: allowed\n", .{description});
    }

    try stdout.flush();
}
