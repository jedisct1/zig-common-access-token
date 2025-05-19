const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const AutoHashMap = std.AutoHashMap;
const testing = std.testing;

const Error = @import("error.zig").Error;
const zbor = @import("zbor.zig");
const util = @import("util.zig");

// Standard CWT claim labels
pub const LABEL_ISS: u64 = 1; // Issuer
pub const LABEL_SUB: u64 = 2; // Subject
pub const LABEL_AUD: u64 = 3; // Audience
pub const LABEL_EXP: u64 = 4; // Expiration Time
pub const LABEL_NBF: u64 = 5; // Not Before
pub const LABEL_IAT: u64 = 6; // Issued At
pub const LABEL_CTI: u64 = 7; // CWT ID
pub const LABEL_CNF: u64 = 8; // Confirmation

// CAT-specific claim labels
pub const LABEL_GEOHASH: u64 = 282; // Geohash
pub const LABEL_CATREPLAY: u64 = 308; // Replay protection
pub const LABEL_CATPOR: u64 = 309; // Proof of possession
pub const LABEL_CATV: u64 = 310; // CAT version
pub const LABEL_CATNIP: u64 = 311; // Network IP
pub const LABEL_CATU: u64 = 312; // URI
pub const LABEL_CATM: u64 = 313; // Methods
pub const LABEL_CATALPN: u64 = 314; // ALPN
pub const LABEL_CATH: u64 = 315; // Headers
pub const LABEL_CATGEOISO3166: u64 = 316; // Geo ISO 3166
pub const LABEL_CATGEOCOORD: u64 = 317; // Geo coordinates
pub const LABEL_CATTPK: u64 = 319; // TPK
pub const LABEL_CATIFDATA: u64 = 320; // IF data
pub const LABEL_CATADPOP: u64 = 321; // AD POP
pub const LABEL_CATIF: u64 = 322; // IF
pub const LABEL_CATR: u64 = 323; // Renewal

/// Represents a value that can be stored in a claim.
///
/// This union supports various data types that can be used in CWT claims:
/// - Strings for text values
/// - Integers for numeric values and timestamps
/// - Bytes for binary data
/// - Arrays for lists of values
/// - Maps for nested structures
pub const ClaimValue = union(enum) {
    String: []const u8,
    Integer: i64,
    Bytes: []const u8,
    Array: ArrayList(ClaimValue),
    Map: AutoHashMap(u64, ClaimValue),

    /// Frees memory associated with the claim value
    pub fn deinit(_: *ClaimValue) void {
        // The actual memory freeing is handled by the Claims.deinit method
    }

    /// Creates a deep clone of the claim value
    pub fn clone(self: ClaimValue, allocator: Allocator) !ClaimValue {
        return switch (self) {
            .String => |str| ClaimValue{ .String = try allocator.dupe(u8, str) },
            .Integer => |int| ClaimValue{ .Integer = int },
            .Bytes => |bytes| ClaimValue{ .Bytes = try allocator.dupe(u8, bytes) },
            .Array => |array| blk: {
                var new_array = ArrayList(ClaimValue).init(allocator);
                errdefer {
                    for (new_array.items) |*item| {
                        item.deinit();
                    }
                    new_array.deinit();
                }

                for (array.items) |item| {
                    try new_array.append(try item.clone(allocator));
                }

                break :blk ClaimValue{ .Array = new_array };
            },
            .Map => |map| blk: {
                var new_map = AutoHashMap(u64, ClaimValue).init(allocator);
                errdefer {
                    var it = new_map.iterator();
                    while (it.next()) |entry| {
                        var value = entry.value_ptr.*;
                        value.deinit();
                    }
                    new_map.deinit();
                }

                var it = map.iterator();
                while (it.next()) |entry| {
                    try new_map.put(entry.key_ptr.*, try entry.value_ptr.clone(allocator));
                }

                break :blk ClaimValue{ .Map = new_map };
            },
        };
    }
};

/// Container for token claims.
///
/// This struct represents the claims in a CAT token. It provides methods for:
/// - Setting and getting standard CWT claims
/// - Setting and getting CAT-specific claims
/// - Converting between different formats
pub const Claims = struct {
    allocator: Allocator,
    claims: AutoHashMap(u64, ClaimValue),

    /// Creates a new Claims object
    pub fn init(allocator: Allocator) Claims {
        return Claims{
            .allocator = allocator,
            .claims = AutoHashMap(u64, ClaimValue).init(allocator),
        };
    }

    /// Frees memory associated with the Claims object
    pub fn deinit(self: *Claims) void {
        var it = self.claims.iterator();
        while (it.next()) |entry| {
            var value = entry.value_ptr.*;
            switch (value) {
                .String => |str| {
                    self.allocator.free(str);
                },
                .Bytes => |bytes| {
                    self.allocator.free(bytes);
                },
                .Array => |*array| {
                    for (array.items) |*item| {
                        item.deinit();
                    }
                    array.deinit();
                },
                .Map => |*map| {
                    var map_it = map.iterator();
                    while (map_it.next()) |map_entry| {
                        var map_value = map_entry.value_ptr.*;
                        map_value.deinit();
                    }
                    map.deinit();
                },
                else => {},
            }
        }
        self.claims.deinit();
    }

    /// Sets the issuer claim
    pub fn setIssuer(self: *Claims, issuer: []const u8) !void {
        const dup_issuer = try self.allocator.dupe(u8, issuer);
        try self.claims.put(LABEL_ISS, ClaimValue{ .String = dup_issuer });
    }

    /// Gets the issuer claim
    pub fn getIssuer(self: Claims) ?[]const u8 {
        if (self.claims.get(LABEL_ISS)) |value| {
            return switch (value) {
                .String => |str| str,
                else => null,
            };
        }
        return null;
    }

    /// Sets the subject claim
    pub fn setSubject(self: *Claims, subject: []const u8) !void {
        const dup_subject = try self.allocator.dupe(u8, subject);
        try self.claims.put(LABEL_SUB, ClaimValue{ .String = dup_subject });
    }

    /// Gets the subject claim
    pub fn getSubject(self: Claims) ?[]const u8 {
        if (self.claims.get(LABEL_SUB)) |value| {
            return switch (value) {
                .String => |str| str,
                else => null,
            };
        }
        return null;
    }

    /// Sets the audience claim
    pub fn setAudience(self: *Claims, audience: []const u8) !void {
        const dup_audience = try self.allocator.dupe(u8, audience);
        try self.claims.put(LABEL_AUD, ClaimValue{ .String = dup_audience });
    }

    /// Gets the audience claim
    pub fn getAudience(self: Claims) ?[]const u8 {
        if (self.claims.get(LABEL_AUD)) |value| {
            return switch (value) {
                .String => |str| str,
                else => null,
            };
        }
        return null;
    }

    /// Sets the expiration time claim
    pub fn setExpiration(self: *Claims, exp: i64) !void {
        try self.claims.put(LABEL_EXP, ClaimValue{ .Integer = exp });
    }

    /// Gets the expiration time claim
    pub fn getExpiration(self: Claims) ?i64 {
        if (self.claims.get(LABEL_EXP)) |value| {
            return switch (value) {
                .Integer => |int| int,
                else => null,
            };
        }
        return null;
    }

    /// Sets the not before claim
    pub fn setNotBefore(self: *Claims, nbf: i64) !void {
        try self.claims.put(LABEL_NBF, ClaimValue{ .Integer = nbf });
    }

    /// Gets the not before claim
    pub fn getNotBefore(self: Claims) ?i64 {
        if (self.claims.get(LABEL_NBF)) |value| {
            return switch (value) {
                .Integer => |int| int,
                else => null,
            };
        }
        return null;
    }

    /// Sets the issued at claim
    pub fn setIssuedAt(self: *Claims, iat: i64) !void {
        try self.claims.put(LABEL_IAT, ClaimValue{ .Integer = iat });
    }

    /// Gets the issued at claim
    pub fn getIssuedAt(self: Claims) ?i64 {
        if (self.claims.get(LABEL_IAT)) |value| {
            return switch (value) {
                .Integer => |int| int,
                else => null,
            };
        }
        return null;
    }

    /// Sets the CWT ID claim
    pub fn setCwtId(self: *Claims, cti: []const u8) !void {
        const dup_cti = try self.allocator.dupe(u8, cti);
        try self.claims.put(LABEL_CTI, ClaimValue{ .Bytes = dup_cti });
    }

    /// Gets the CWT ID claim
    pub fn getCwtId(self: Claims) ?[]const u8 {
        if (self.claims.get(LABEL_CTI)) |value| {
            return switch (value) {
                .Bytes => |bytes| bytes,
                else => null,
            };
        }
        return null;
    }

    /// Sets the CAT version claim
    pub fn setCatVersion(self: *Claims, version: i64) !void {
        try self.claims.put(LABEL_CATV, ClaimValue{ .Integer = version });
    }

    /// Gets the CAT version claim
    pub fn getCatVersion(self: Claims) ?i64 {
        if (self.claims.get(LABEL_CATV)) |value| {
            return switch (value) {
                .Integer => |int| int,
                else => null,
            };
        }
        return null;
    }

    /// Sets a generic claim
    pub fn setClaim(self: *Claims, label: u64, value: ClaimValue) !void {
        try self.claims.put(label, try value.clone(self.allocator));
    }

    /// Gets a generic claim
    pub fn getClaim(self: Claims, label: u64) ?ClaimValue {
        return self.claims.get(label);
    }

    /// Serializes the claims to CBOR
    pub fn toCbor(self: Claims, allocator: Allocator) ![]u8 {
        var encoder = zbor.Encoder.init(allocator);
        defer encoder.deinit();

        // Start a map with the number of claims
        try encoder.beginMap(@intCast(self.claims.count()));

        // Add each claim to the map
        var it = self.claims.iterator();
        while (it.next()) |entry| {
            const label = entry.key_ptr.*;
            const value = entry.value_ptr.*;

            // Add the label as an unsigned integer
            try encoder.pushInt(label);

            // Add the value based on its type
            switch (value) {
                .String => |str| try encoder.pushText(str),
                .Integer => |int| try encoder.pushInt(int),
                .Bytes => |bytes| try encoder.pushBytes(bytes),
                .Array => |array| {
                    try encoder.beginArray(@intCast(array.items.len));
                    for (array.items) |item| {
                        switch (item) {
                            .String => |str| try encoder.pushText(str),
                            .Integer => |int| try encoder.pushInt(int),
                            .Bytes => |bytes| try encoder.pushBytes(bytes),
                            else => return Error.CborEncodingError,
                        }
                    }
                    try encoder.endArray();
                },
                .Map => |map| {
                    try encoder.beginMap(@intCast(map.count()));
                    var map_it = map.iterator();
                    while (map_it.next()) |map_entry| {
                        const map_label = map_entry.key_ptr.*;
                        const map_value = map_entry.value_ptr.*;

                        try encoder.pushInt(map_label);

                        switch (map_value) {
                            .String => |str| try encoder.pushText(str),
                            .Integer => |int| try encoder.pushInt(int),
                            .Bytes => |bytes| try encoder.pushBytes(bytes),
                            else => return Error.CborEncodingError,
                        }
                    }
                    try encoder.endMap();
                },
            }
        }

        // End the map
        try encoder.endMap();

        // Get the encoded CBOR
        return encoder.finish();
    }

    /// Deserializes claims from CBOR
    pub fn fromCbor(allocator: Allocator, cbor_data: []const u8) !Claims {
        var claims = Claims.init(allocator);
        errdefer claims.deinit();

        var decoder = zbor.Decoder.init(cbor_data, allocator);
        defer decoder.deinit();

        // Expect a map
        const map_len = try decoder.beginMap();

        // Read each claim from the map
        var i: usize = 0;
        while (i < map_len) : (i += 1) {
            // Read the label
            const label = try decoder.readInt(u64);

            // Read the value based on its type
            const major_type = try decoder.peekMajorType();

            switch (major_type) {
                .TextString => {
                    const str = try decoder.readText(allocator);
                    defer allocator.free(str);
                    try claims.setClaim(label, ClaimValue{ .String = try allocator.dupe(u8, str) });
                },
                .UnsignedInt, .NegativeInt => {
                    const int = try decoder.readInt(i64);
                    try claims.setClaim(label, ClaimValue{ .Integer = int });
                },
                .ByteString => {
                    const bytes = try decoder.readBytes(allocator);
                    defer allocator.free(bytes);
                    try claims.setClaim(label, ClaimValue{ .Bytes = try allocator.dupe(u8, bytes) });
                },
                .Array => {
                    const array_len = try decoder.beginArray();
                    var array = ArrayList(ClaimValue).init(allocator);
                    errdefer {
                        for (array.items) |*item| {
                            item.deinit();
                        }
                        array.deinit();
                    }

                    var j: usize = 0;
                    while (j < array_len) : (j += 1) {
                        const item_major_type = try decoder.peekMajorType();

                        switch (item_major_type) {
                            .TextString => {
                                const str = try decoder.readText(allocator);
                                try array.append(ClaimValue{ .String = str });
                            },
                            .UnsignedInt, .NegativeInt => {
                                const int = try decoder.readInt(i64);
                                try array.append(ClaimValue{ .Integer = int });
                            },
                            .ByteString => {
                                const bytes = try decoder.readBytes(allocator);
                                try array.append(ClaimValue{ .Bytes = bytes });
                            },
                            else => return Error.CborDecodingError,
                        }
                    }

                    try decoder.endArray();
                    try claims.setClaim(label, ClaimValue{ .Array = array });
                },
                .Map => {
                    const map_len2 = try decoder.beginMap();
                    var map = AutoHashMap(u64, ClaimValue).init(allocator);
                    errdefer {
                        var map_it = map.iterator();
                        while (map_it.next()) |map_entry| {
                            var map_value = map_entry.value_ptr.*;
                            map_value.deinit();
                        }
                        map.deinit();
                    }

                    var j: usize = 0;
                    while (j < map_len2) : (j += 1) {
                        const map_label = try decoder.readInt(u64);
                        const item_major_type = try decoder.peekMajorType();

                        switch (item_major_type) {
                            .TextString => {
                                const str = try decoder.readText(allocator);
                                try map.put(map_label, ClaimValue{ .String = str });
                            },
                            .UnsignedInt, .NegativeInt => {
                                const int = try decoder.readInt(i64);
                                try map.put(map_label, ClaimValue{ .Integer = int });
                            },
                            .ByteString => {
                                const bytes = try decoder.readBytes(allocator);
                                try map.put(map_label, ClaimValue{ .Bytes = bytes });
                            },
                            else => return Error.CborDecodingError,
                        }
                    }

                    try decoder.endMap();
                    try claims.setClaim(label, ClaimValue{ .Map = map });
                },
                else => return Error.CborDecodingError,
            }
        }

        try decoder.endMap();

        return claims;
    }
};

test "claims basic operations" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var claims = Claims.init(allocator);
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
