const std = @import("std");
const testing = std.testing;
const cat = @import("cat");
const moqt = cat.moqt;

/// Encodes scopes into a payload and parses them back, the way a relay will see them
fn roundTrip(allocator: std.mem.Allocator, scopes: []const moqt.Scope) !moqt.Claim {
    var claims = cat.Claims.init(allocator);
    defer claims.deinit();
    try claims.setMoqt(scopes);

    const cbor = try claims.toCbor(allocator);
    defer allocator.free(cbor);

    var decoded = try cat.Claims.fromCbor(allocator, cbor);
    defer decoded.deinit();
    return (try decoded.getMoqt(allocator)).?;
}

fn decodeHex(buf: []u8, hex: []const u8) !cat.Claims {
    return cat.Claims.fromCbor(testing.allocator, try std.fmt.hexToBytes(buf, hex));
}

test "draft test vectors (appendix A.5)" {
    const Vector = struct {
        payload: []const u8,
        scopes: []const moqt.Scope,
        reval: ?f64 = null,
        requests: []const struct { moqt.Action, []const []const u8, []const u8, bool },
    };
    const vectors = [_]Vector{
        .{
            .payload = "a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542801901478183820206824b6578616d706c652e636f6d45616c696365820146766964656f2d",
            .scopes = &.{.{ .actions = &.{ .PublishNamespace, .Publish }, .namespace = &.{ .{ .Exact = "example.com" }, .{ .Exact = "alice" } }, .track = .{ .Prefix = "video-" } }},
            .requests = &.{
                .{ .PublishNamespace, &.{ "example.com", "alice" }, "video-hd", true },
                .{ .Publish, &.{ "example.com", "alice" }, "video-sd", true },
                .{ .Publish, &.{ "example.com", "alice" }, "audio-main", false },
                .{ .Subscribe, &.{ "example.com", "alice" }, "video-hd", false },
                .{ .Publish, &.{ "example.com", "bob" }, "video-hd", false },
            },
        },
        .{
            .payload = "a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a6555428019014781828303040781820152636f6e666572656e63652e6578616d706c65",
            .scopes = &.{.{ .actions = &.{ .SubscribeNamespace, .Subscribe, .Fetch }, .namespace = &.{.{ .Prefix = "conference.example" }} }},
            .requests = &.{
                .{ .Subscribe, &.{"conference.example.room1"}, "audio", true },
                .{ .Fetch, &.{"conference.example.room2"}, "video", true },
                .{ .Subscribe, &.{"other.domain"}, "audio", false },
                .{ .Publish, &.{"conference.example.room1"}, "audio", false },
            },
        },
        .{
            .payload = "a401781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542801901478282820206824c6c6976652e6578616d706c654873747564696f2d61828204078182014c6c6976652e6578616d706c65190148f95cb0",
            .scopes = &.{
                .{ .actions = &.{ .PublishNamespace, .Publish }, .namespace = &.{ .{ .Exact = "live.example" }, .{ .Exact = "studio-a" } } },
                .{ .actions = &.{ .Subscribe, .Fetch }, .namespace = &.{.{ .Prefix = "live.example" }} },
            },
            .reval = 300,
            .requests = &.{
                .{ .Publish, &.{ "live.example", "studio-a" }, "cam1", true },
                .{ .Subscribe, &.{"live.example.studio-b"}, "cam1", true },
                .{ .Publish, &.{ "live.example", "studio-b" }, "cam1", false },
                .{ .PublishNamespace, &.{ "other.example", "studio-a" }, "", false },
            },
        },
        .{
            .payload = "a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a65554280190147818189000102030405060708",
            .scopes = &.{.{ .actions = &.{ .ClientSetup, .ServerSetup, .PublishNamespace, .SubscribeNamespace, .Subscribe, .RequestUpdate, .Publish, .Fetch, .TrackStatus } }},
            .requests = &.{
                .{ .ClientSetup, &.{"any.namespace"}, "any-track", true },
                .{ .Publish, &.{"any.namespace"}, "any-track", true },
                .{ .TrackStatus, &.{"any.namespace"}, "status", true },
            },
        },
        .{
            .payload = "a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a65554280190147818381048182024c2e6578616d706c652e636f6d8202462d617564696f",
            .scopes = &.{.{ .actions = &.{.Subscribe}, .namespace = &.{.{ .Suffix = ".example.com" }}, .track = .{ .Suffix = "-audio" } }},
            .requests = &.{
                .{ .Subscribe, &.{"cdn.example.com"}, "stream1-audio", true },
                .{ .Subscribe, &.{"cdn.example.com"}, "stream1-video", false },
                .{ .Subscribe, &.{"cdn.other.org"}, "stream1-audio", false },
            },
        },
    };

    for (vectors) |vector| {
        var buf: [256]u8 = undefined;
        var claims = try decodeHex(&buf, vector.payload);
        defer claims.deinit();
        try testing.expectEqual(vector.reval, try claims.getMoqtReval());

        var claim = (try claims.getMoqt(testing.allocator)).?;
        defer claim.deinit();
        for (vector.requests) |request| {
            const action, const namespace, const track, const expected = request;
            try testing.expectEqual(expected, claim.permits(.{ .action = action, .namespace = namespace, .track = track }));
        }

        // The same scopes must encode to the exact bytes of the vector.
        var built = cat.Claims.init(testing.allocator);
        defer built.deinit();
        try built.setMoqt(vector.scopes);
        const cbor = try built.toCbor(testing.allocator);
        defer testing.allocator.free(cbor);
        try testing.expect(std.mem.indexOf(u8, try std.fmt.hexToBytes(&buf, vector.payload), cbor[1..]) != null);
    }
}

test "draft examples (sections 2.1.1 and 2.1.2)" {
    const actions: []const moqt.Action = &.{ .PublishNamespace, .SubscribeNamespace, .Publish, .Fetch };
    const example_com: []const moqt.BinMatch = &.{ .{ .Exact = "example" }, .{ .Exact = "com" } };
    const Example = struct { scopes: []const moqt.Scope, names: []const struct { []const []const u8, []const u8, bool } };
    const examples = [_]Example{
        .{
            .scopes = &.{.{ .actions = actions, .namespace = example_com, .exact_namespace_length = true, .track = .{ .Exact = "/bob" } }},
            .names = &.{
                .{ &.{ "example", "com" }, "/bob", true },
                .{ &.{ "example", "com" }, "", false },
                .{ &.{ "example", "com" }, "/bob/123", false },
                .{ &.{ "example", "com" }, "/alice", false },
                .{ &.{ "example", "com" }, "/bob/logs", false },
                .{ &.{ "alternate", "example", "com" }, "/bob", false },
                .{ &.{"12345"}, "", false },
                .{ &.{"example"}, "com/bob", false },
                .{ &.{ "example", "com", "/bob" }, "", false },
                .{ &.{ "example", "com", "" }, "/bob", false },
            },
        },
        .{
            .scopes = &.{.{ .actions = actions, .namespace = example_com, .exact_namespace_length = true, .track = .{ .Prefix = "/bob" } }},
            .names = &.{
                .{ &.{ "example", "com" }, "/bob", true },
                .{ &.{ "example", "com" }, "/bob/123", true },
                .{ &.{ "example", "com" }, "/bob/logs", true },
                .{ &.{ "example", "com" }, "", false },
                .{ &.{ "example", "com" }, "/alice", false },
                .{ &.{ "alternate", "example", "com" }, "/bob", false },
                .{ &.{"12345"}, "", false },
                .{ &.{"example"}, "com/bob", false },
            },
        },
        .{
            .scopes = &.{.{ .actions = actions, .namespace = example_com }},
            .names = &.{
                .{ &.{ "example", "com" }, "/bob", true },
                .{ &.{ "example", "com", "" }, "/bob", true },
                .{ &.{ "example", "com", "bob" }, "/bob", true },
                .{ &.{ "example", "com" }, "", true },
                .{ &.{ "example", "com", "/bob" }, "", true },
                .{ &.{ "alternate", "example", "com" }, "/bob", false },
                .{ &.{"12345"}, "", false },
                .{ &.{"example"}, "com/bob", false },
            },
        },
        .{
            .scopes = &.{.{ .actions = actions, .namespace = &.{ .{ .Exact = "example" }, .{ .Prefix = "user-" } }, .exact_namespace_length = true, .track = .{ .Exact = "/data" } }},
            .names = &.{
                .{ &.{ "example", "user-alice" }, "/data", true },
                .{ &.{ "example", "user-" }, "/data", true },
                .{ &.{ "example", "alice" }, "/data", false },
                .{ &.{ "example", "user-alice", "extra" }, "/data", false },
                .{ &.{ "example", "USER-alice" }, "/data", false },
                .{ &.{"example"}, "/data", false },
            },
        },
        .{
            .scopes = &.{.{ .actions = &.{.Publish}, .namespace = example_com, .exact_namespace_length = true, .track = .{ .Suffix = ".json" } }},
            .names = &.{
                .{ &.{ "example", "com" }, "data.json", true },
                .{ &.{ "example", "com" }, ".json", true },
                .{ &.{ "example", "com" }, "data.xml", false },
                .{ &.{ "example", "com" }, "json", false },
                .{ &.{ "example", "com" }, "data.JSON", false },
                .{ &.{ "example", "com" }, "data.json.bak", false },
            },
        },
        .{
            .scopes = &.{
                .{ .actions = &.{.Publish}, .namespace = example_com, .exact_namespace_length = true, .track = .{ .Prefix = "/bob" } },
                .{ .actions = &.{.Publish}, .namespace = example_com, .exact_namespace_length = true, .track = .{ .Exact = "/logs/12345/bob" } },
            },
            .names = &.{
                .{ &.{ "example", "com" }, "/bob/123", true },
                .{ &.{ "example", "com" }, "/logs/12345/bob", true },
                .{ &.{ "example", "com" }, "", false },
            },
        },
    };

    for (examples) |example| {
        var claim = try roundTrip(testing.allocator, example.scopes);
        defer claim.deinit();
        for (example.names) |name| {
            const namespace, const track, const allowed = name;
            try testing.expectEqual(allowed, claim.permits(.{ .action = .Publish, .namespace = namespace, .track = track }));
        }
    }
}

test "which parts of a scope apply to each action" {
    var claim = try roundTrip(testing.allocator, &.{
        .{ .actions = &.{ .ClientSetup, .PublishNamespace, .SubscribeNamespace, .Subscribe }, .namespace = &.{ .{ .Exact = "example" }, .{ .Exact = "com" } }, .track = .{ .Exact = "live" } },
        .{ .actions = &.{.Fetch}, .track = .{ .Exact = "vod" } },
    });
    defer claim.deinit();
    const example_com: []const []const u8 = &.{ "example", "com" };

    // Setup actions have nothing to match besides the action itself.
    try testing.expect(claim.permits(.{ .action = .ClientSetup }));
    try testing.expect(!claim.permits(.{ .action = .ServerSetup }));

    // Namespace actions ignore the track match, but can't ask for a shorter prefix than the scope.
    try testing.expect(claim.permits(.{ .action = .PublishNamespace, .namespace = example_com }));
    try testing.expect(claim.permits(.{ .action = .SubscribeNamespace, .namespace = &.{ "example", "com", "sports" } }));
    try testing.expect(!claim.permits(.{ .action = .SubscribeNamespace, .namespace = &.{"example"} }));

    // Track actions fail when the caller leaves out the track name.
    try testing.expect(claim.permits(.{ .action = .Subscribe, .namespace = example_com, .track = "live" }));
    try testing.expect(!claim.permits(.{ .action = .Subscribe, .namespace = example_com }));

    // A track match without a namespace match accepts any namespace.
    try testing.expect(claim.permits(.{ .action = .Fetch, .namespace = &.{"anything"}, .track = "vod" }));
    try testing.expect(!claim.permits(.{ .action = .Fetch, .namespace = &.{"anything"}, .track = "live" }));
}

test "malformed moqt claims are rejected" {
    const malformed = [_][]const u8{
        "a119014780", // empty claim
        "a11901478180", // empty scope
        "a1190147818180", // empty actions
        "a11901478184810481416141744178", // too many scope elements
        "a11901478181816134", // text action
        "a11901478104", // scope is not an array
        "a11901478182810480", // empty namespace matches
        "a11901478182810482f64161", // nil before the last namespace match
        "a119014781838104814161f6", // nil track match
        "a1190147818281048182034161", // unknown match type
        "a1190147818281048182016161", // text pattern
        "a119014781828104816161", // text exact match
        "a11901478182810481830141614162", // match with three elements
        "a1190147818281044161", // namespace given as a byte string
        "a1190147a10102", // claim is a map
    };
    for (malformed) |hex| {
        var buf: [64]u8 = undefined;
        var claims = try decodeHex(&buf, hex);
        defer claims.deinit();
        try testing.expectError(error.InvalidMoqtClaim, claims.getMoqt(testing.allocator));
    }

    // Unknown action codes are valid, they just never match.
    var buf: [64]u8 = undefined;
    var claims = try decodeHex(&buf, "a1190147818182186304");
    defer claims.deinit();
    var claim = (try claims.getMoqt(testing.allocator)).?;
    defer claim.deinit();
    try testing.expect(claim.permits(.{ .action = .Subscribe, .namespace = &.{"a"}, .track = "b" }));
    try testing.expect(!claim.permits(.{ .action = .Publish, .namespace = &.{"a"}, .track = "b" }));
}

test "moqt-reval values" {
    try testing.expectEqual(300, try moqt.parseReval(.{ .Integer = 300 }));
    try testing.expectEqual(0.5, try moqt.parseReval(.{ .Float = 0.5 }));
    try testing.expectEqual(null, try moqt.parseReval(.{ .Integer = 0 }));

    const invalid = [_]cat.ClaimValue{ .{ .Integer = -1 }, .{ .Float = std.math.nan(f64) }, .{ .Float = std.math.inf(f64) }, .{ .String = "300" } };
    for (invalid) |value| {
        try testing.expectError(error.InvalidMoqtClaim, moqt.parseReval(value));
    }
}

test "relays authorize MoQT requests" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var keys = std.StringHashMap([]const u8).init(allocator);
    try keys.put("relay", "relay-secret");
    const relay = cat.Cat.init(allocator, .{ .keys = keys, .expect_cwt_tag = true, .io = testing.io });
    const generate_options: cat.CatGenerateOptions = .{ .validation_type = .Mac, .alg = "HS256", .kid = "relay", .generate_cwt_id = false };

    var claims = cat.Claims.init(allocator);
    try claims.setIssuer("issuer");
    try claims.setMoqt(&.{.{ .actions = &.{ .PublishNamespace, .Publish }, .namespace = &.{ .{ .Exact = "example.com" }, .{ .Exact = "alice" } }, .track = .{ .Prefix = "video-" } }});
    try claims.setMoqtReval(300);
    const token = try relay.generate(claims, generate_options);

    const publish: moqt.Request = .{ .action = .Publish, .namespace = &.{ "example.com", "alice" }, .track = "video-hd" };
    const subscribe: moqt.Request = .{ .action = .Subscribe, .namespace = publish.namespace, .track = publish.track };
    var validated = try relay.validate(token, .Mac, .{ .issuer = "issuer", .moqt_request = publish, .moqt_min_reval_interval = 60 });
    try testing.expectEqual(300, try validated.getMoqtReval());
    try testing.expectError(error.MoqtNotAuthorized, relay.validate(token, .Mac, .{ .issuer = "issuer", .moqt_request = subscribe, .moqt_min_reval_interval = 60 }));

    // A relay must reject tokens that it can't revalidate as often as they ask.
    try testing.expectError(error.MoqtRevalidationUnsupported, relay.validate(token, .Mac, .{ .issuer = "issuer", .moqt_request = publish }));
    try testing.expectError(error.MoqtRevalidationUnsupported, relay.validate(token, .Mac, .{ .issuer = "issuer", .moqt_request = publish, .moqt_min_reval_interval = 600 }));

    // Without a moqt claim, a token allows no MoQT action at all.
    var plain = cat.Claims.init(allocator);
    try plain.setIssuer("issuer");
    const plain_token = try relay.generate(plain, generate_options);
    try testing.expectError(error.MoqtNotAuthorized, relay.validate(plain_token, .Mac, .{ .issuer = "issuer", .moqt_request = publish }));
}

fn roundTripAndFree(allocator: std.mem.Allocator, scopes: []const moqt.Scope) !void {
    var claim = try roundTrip(allocator, scopes);
    claim.deinit();
}

test "no leaks when allocations fail" {
    const scopes = [_]moqt.Scope{
        .{ .actions = &.{ .PublishNamespace, .Publish }, .namespace = &.{ .{ .Exact = "example" }, .{ .Prefix = "user-" } }, .exact_namespace_length = true, .track = .{ .Suffix = ".json" } },
        .{ .actions = &.{.Fetch}, .track = .{ .Exact = "vod" } },
    };
    try testing.checkAllAllocationFailures(testing.allocator, roundTripAndFree, .{&scopes});
}
