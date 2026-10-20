//! Media over QUIC Transport (MoQT) authorization with Common Access Tokens, as defined in draft-ietf-moq-c4m.
//!
//! The `moqt` claim is a list of scopes. Each scope lists the MoQT actions it allows, and optionally the namespaces and track names they apply to.
//! A request is allowed if any scope allows it. Once a relay receives a token, everything else is blocked.
//!
//! The draft doesn't say how namespace and track matches apply to actions without a namespace or a track.
//! Here, setup actions only need to be listed, namespace actions also check the namespace, and track actions check both.
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Error = @import("error.zig").Error;
const ClaimValue = @import("claims.zig").ClaimValue;

pub const MATCH_PREFIX: i64 = 1;
pub const MATCH_SUFFIX: i64 = 2;

/// MoQT actions, with their codes in the `moqt` claim.
/// Unknown codes in a token are kept, but they never match a known action.
pub const Action = enum(i64) {
    ClientSetup = 0,
    ServerSetup = 1,
    PublishNamespace = 2,
    SubscribeNamespace = 3,
    Subscribe = 4,
    RequestUpdate = 5,
    Publish = 6,
    Fetch = 7,
    TrackStatus = 8,
    _,

    /// What the action applies to, which decides the parts of a scope to check
    pub fn target(self: Action) Target {
        return switch (self) {
            .ClientSetup, .ServerSetup => .Session,
            .PublishNamespace, .SubscribeNamespace => .Namespace,
            .Subscribe, .RequestUpdate, .Publish, .Fetch, .TrackStatus => .Track,
            // Unknown actions get the strictest checks.
            _ => .Track,
        };
    }
};

pub const Target = enum {
    Session,
    Namespace,
    Track,
};

/// A bytewise match on a namespace field or a track name
pub const BinMatch = union(enum) {
    Exact: []const u8,
    Prefix: []const u8,
    Suffix: []const u8,

    pub fn matches(self: BinMatch, value: []const u8) bool {
        return switch (self) {
            .Exact => |pattern| std.mem.eql(u8, value, pattern),
            .Prefix => |pattern| std.mem.startsWith(u8, value, pattern),
            .Suffix => |pattern| std.mem.endsWith(u8, value, pattern),
        };
    }

    fn toClaimValue(self: BinMatch, allocator: Allocator) !ClaimValue {
        const match_type: i64, const pattern = switch (self) {
            .Exact => |pattern| return ClaimValue{ .Bytes = try allocator.dupe(u8, pattern) },
            .Prefix => |pattern| .{ MATCH_PREFIX, pattern },
            .Suffix => |pattern| .{ MATCH_SUFFIX, pattern },
        };
        var array: ArrayList(ClaimValue) = try .initCapacity(allocator, 2);
        errdefer array.deinit(allocator);
        array.appendAssumeCapacity(.{ .Integer = match_type });
        array.appendAssumeCapacity(.{ .Bytes = try allocator.dupe(u8, pattern) });
        return ClaimValue{ .Array = array };
    }

    fn parse(allocator: Allocator, value: ClaimValue) !BinMatch {
        switch (value) {
            .Bytes => |pattern| return .{ .Exact = try allocator.dupe(u8, pattern) },
            .Array => |array| {
                if (array.items.len != 2) return Error.InvalidMoqtClaim;
                const match_type = switch (array.items[0]) {
                    .Integer => |int| int,
                    else => return Error.InvalidMoqtClaim,
                };
                const pattern = switch (array.items[1]) {
                    .Bytes => |bytes| try allocator.dupe(u8, bytes),
                    else => return Error.InvalidMoqtClaim,
                };
                return switch (match_type) {
                    MATCH_PREFIX => .{ .Prefix = pattern },
                    MATCH_SUFFIX => .{ .Suffix = pattern },
                    else => Error.InvalidMoqtClaim,
                };
            },
            else => return Error.InvalidMoqtClaim,
        }
    }
};

/// One entry of the `moqt` claim
pub const Scope = struct {
    /// Allowed actions. There must be at least one.
    actions: []const Action,

    /// Matches for the first namespace fields, in order. Longer namespaces are also allowed, unless `exact_namespace_length` is set.
    namespace: []const BinMatch = &.{},

    /// Only allow namespaces with exactly one field per match
    exact_namespace_length: bool = false,

    /// Match for the track name, or null to allow any track
    track: ?BinMatch = null,

    pub fn permits(self: Scope, request: Request) bool {
        if (std.mem.indexOfScalar(Action, self.actions, request.action) == null) return false;
        const target = request.action.target();
        if (target == .Session) return true;

        // A shorter namespace would reach beyond the scope, for example when subscribing to a namespace prefix.
        const namespace = request.namespace;
        if (namespace.len < self.namespace.len) return false;
        if (self.exact_namespace_length and namespace.len != self.namespace.len) return false;
        for (self.namespace, namespace[0..self.namespace.len]) |match, field| {
            if (!match.matches(field)) return false;
        }
        if (target == .Namespace) return true;

        const track = request.track orelse return false;
        const match = self.track orelse return true;
        return match.matches(track);
    }

    fn toClaimValue(self: Scope, allocator: Allocator) !ClaimValue {
        if (self.actions.len == 0) return Error.InvalidMoqtClaim;

        var scope = ClaimValue{ .Array = .empty };
        errdefer scope.deinit(allocator);

        var actions: ArrayList(ClaimValue) = try .initCapacity(allocator, self.actions.len);
        for (self.actions) |action| actions.appendAssumeCapacity(.{ .Integer = @backingInt(action) });
        try appendOwned(allocator, &scope.Array, .{ .Array = actions });

        if (self.namespace.len > 0 or self.exact_namespace_length or self.track != null) {
            try appendOwned(allocator, &scope.Array, try self.namespaceToClaimValue(allocator));
        }
        if (self.track) |track| {
            try appendOwned(allocator, &scope.Array, try track.toClaimValue(allocator));
        }
        return scope;
    }

    fn namespaceToClaimValue(self: Scope, allocator: Allocator) !ClaimValue {
        var namespace = ClaimValue{ .Array = .empty };
        errdefer namespace.deinit(allocator);

        for (self.namespace) |match| {
            try appendOwned(allocator, &namespace.Array, try match.toClaimValue(allocator));
        }
        if (self.exact_namespace_length) try namespace.Array.append(allocator, .Null);

        // A track match can only follow a namespace match. An empty prefix accepts any namespace, since they all have a first field.
        if (namespace.Array.items.len == 0) {
            const any_field: BinMatch = .{ .Prefix = "" };
            try appendOwned(allocator, &namespace.Array, try any_field.toClaimValue(allocator));
        }
        return namespace;
    }

    fn parse(allocator: Allocator, value: ClaimValue) !Scope {
        const parts = try arrayItems(value);
        if (parts.len == 0 or parts.len > 3) return Error.InvalidMoqtClaim;

        const codes = try arrayItems(parts[0]);
        if (codes.len == 0) return Error.InvalidMoqtClaim;
        const actions = try allocator.alloc(Action, codes.len);
        for (codes, actions) |code, *action| {
            action.* = switch (code) {
                .Integer => |int| @fromBackingInt(int),
                else => return Error.InvalidMoqtClaim,
            };
        }
        var scope: Scope = .{ .actions = actions };

        if (parts.len > 1) {
            var matches = try arrayItems(parts[1]);
            if (matches.len == 0) return Error.InvalidMoqtClaim;

            // Nil can only come last. Anywhere else, it fails to parse as a match.
            if (matches[matches.len - 1] == .Null) {
                scope.exact_namespace_length = true;
                matches = matches[0 .. matches.len - 1];
            }
            const namespace = try allocator.alloc(BinMatch, matches.len);
            for (matches, namespace) |match, *field| field.* = try BinMatch.parse(allocator, match);
            scope.namespace = namespace;
        }
        if (parts.len > 2) scope.track = try BinMatch.parse(allocator, parts[2]);
        return scope;
    }
};

/// A MoQT request to authorize
pub const Request = struct {
    action: Action,

    /// Track namespace fields, not needed for setup actions
    namespace: []const []const u8 = &.{},

    /// Track name, only needed for track actions
    track: ?[]const u8 = null,
};

/// A parsed `moqt` claim. It owns a copy of the data, so it outlives the claims it came from.
pub const Claim = struct {
    arena: std.heap.ArenaAllocator,
    scopes: []const Scope,

    /// Anything outside the draft's grammar is rejected, so a malformed scope can never widen access.
    pub fn parse(allocator: Allocator, value: ClaimValue) !Claim {
        var arena: std.heap.ArenaAllocator = .init(allocator);
        errdefer arena.deinit();

        const items = try arrayItems(value);
        if (items.len == 0) return Error.InvalidMoqtClaim;
        const scopes = try arena.allocator().alloc(Scope, items.len);
        for (items, scopes) |item, *scope| scope.* = try Scope.parse(arena.allocator(), item);
        return .{ .arena = arena, .scopes = scopes };
    }

    pub fn deinit(self: *Claim) void {
        self.arena.deinit();
    }

    pub fn permits(self: Claim, request: Request) bool {
        for (self.scopes) |scope| {
            if (scope.permits(request)) return true;
        }
        return false;
    }
};

/// Encodes scopes as a `moqt` claim value. It fails if there are no scopes, or if a scope has no actions.
pub fn toClaimValue(allocator: Allocator, scopes: []const Scope) !ClaimValue {
    if (scopes.len == 0) return Error.InvalidMoqtClaim;

    var claim = ClaimValue{ .Array = .empty };
    errdefer claim.deinit(allocator);
    for (scopes) |scope| {
        try appendOwned(allocator, &claim.Array, try scope.toClaimValue(allocator));
    }
    return claim;
}

/// Reads a `moqt-reval` interval in seconds. Zero means the token must not be revalidated, and gives null.
pub fn parseReval(value: ClaimValue) !?f64 {
    const seconds = value.asNumber() orelse return Error.InvalidMoqtClaim;
    if (!std.math.isFinite(seconds) or seconds < 0) return Error.InvalidMoqtClaim;
    return if (seconds == 0) null else seconds;
}

fn arrayItems(value: ClaimValue) ![]const ClaimValue {
    return switch (value) {
        .Array => |array| array.items,
        else => Error.InvalidMoqtClaim,
    };
}

/// Appends a value to a list, freeing it if that fails
fn appendOwned(allocator: Allocator, list: *ArrayList(ClaimValue), value: ClaimValue) !void {
    var owned = value;
    errdefer owned.deinit(allocator);
    try list.append(allocator, owned);
}
