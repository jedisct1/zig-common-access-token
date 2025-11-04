const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const AutoHashMap = std.AutoHashMap;
const testing = std.testing;

const Error = @import("error.zig").Error;
const zbor = @import("zbor.zig");
const util = @import("util.zig");

pub const LABEL_ISS: u64 = 1;
pub const LABEL_SUB: u64 = 2;
pub const LABEL_AUD: u64 = 3;
pub const LABEL_EXP: u64 = 4;
pub const LABEL_NBF: u64 = 5;
pub const LABEL_IAT: u64 = 6;
pub const LABEL_CTI: u64 = 7;
pub const LABEL_CNF: u64 = 8;

pub const LABEL_GEOHASH: u64 = 282;
pub const LABEL_CATREPLAY: u64 = 308;
pub const LABEL_CATPOR: u64 = 309;
pub const LABEL_CATV: u64 = 310;
pub const LABEL_CATNIP: u64 = 311;
pub const LABEL_CATU: u64 = 312;
pub const LABEL_CATM: u64 = 313;
pub const LABEL_CATALPN: u64 = 314;
pub const LABEL_CATH: u64 = 315;
pub const LABEL_CATGEOISO3166: u64 = 316;
pub const LABEL_CATGEOCOORD: u64 = 317;
pub const LABEL_CATGEOALT: u64 = 318;
pub const LABEL_CATTPK: u64 = 319;
pub const LABEL_CATIFDATA: u64 = 320;
pub const LABEL_CATDPOP: u64 = 321;
pub const LABEL_CATIF: u64 = 322;
pub const LABEL_CATR: u64 = 323;

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
    pub fn deinit(self: *ClaimValue, allocator: Allocator) void {
        switch (self.*) {
            .String => |str| allocator.free(str),
            .Bytes => |bytes| allocator.free(bytes),
            .Array => |*array| {
                for (array.items) |*item| {
                    item.deinit(allocator);
                }
                array.deinit(allocator);
            },
            .Map => |*map| {
                var it = map.iterator();
                while (it.next()) |entry| {
                    var value = entry.value_ptr.*;
                    value.deinit(allocator);
                }
                map.deinit();
            },
            .Integer => {},
        }
    }

    /// Creates a deep clone of the claim value
    pub fn clone(self: ClaimValue, allocator: Allocator) !ClaimValue {
        return switch (self) {
            .String => |str| ClaimValue{ .String = try allocator.dupe(u8, str) },
            .Integer => |int| ClaimValue{ .Integer = int },
            .Bytes => |bytes| ClaimValue{ .Bytes = try allocator.dupe(u8, bytes) },
            .Array => |array| blk: {
                var new_array = ArrayList(ClaimValue){};
                errdefer {
                    for (new_array.items) |*item| {
                        item.deinit(allocator);
                    }
                    new_array.deinit(allocator);
                }

                for (array.items) |item| {
                    try new_array.append(allocator, try item.clone(allocator));
                }

                break :blk ClaimValue{ .Array = new_array };
            },
            .Map => |map| blk: {
                var new_map = AutoHashMap(u64, ClaimValue).init(allocator);
                errdefer {
                    var it = new_map.iterator();
                    while (it.next()) |entry| {
                        var value = entry.value_ptr.*;
                        value.deinit(allocator);
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
            value.deinit(self.allocator);
        }
        self.claims.deinit();
    }

    fn setStringClaim(self: *Claims, label: u64, value: []const u8) !void {
        const dup = try self.allocator.dupe(u8, value);
        try self.claims.put(label, ClaimValue{ .String = dup });
    }

    fn getStringClaim(self: Claims, label: u64) ?[]const u8 {
        return if (self.claims.get(label)) |value| switch (value) {
            .String => |str| str,
            else => null,
        } else null;
    }

    fn setIntClaim(self: *Claims, label: u64, value: i64) !void {
        try self.claims.put(label, ClaimValue{ .Integer = value });
    }

    fn getIntClaim(self: Claims, label: u64) ?i64 {
        return if (self.claims.get(label)) |value| switch (value) {
            .Integer => |int| int,
            else => null,
        } else null;
    }

    /// Sets the issuer claim
    pub fn setIssuer(self: *Claims, issuer: []const u8) !void {
        try self.setStringClaim(LABEL_ISS, issuer);
    }

    /// Gets the issuer claim
    pub fn getIssuer(self: Claims) ?[]const u8 {
        return self.getStringClaim(LABEL_ISS);
    }

    /// Sets the subject claim
    pub fn setSubject(self: *Claims, subject: []const u8) !void {
        try self.setStringClaim(LABEL_SUB, subject);
    }

    /// Gets the subject claim
    pub fn getSubject(self: Claims) ?[]const u8 {
        return self.getStringClaim(LABEL_SUB);
    }

    /// Sets the audience claim
    pub fn setAudience(self: *Claims, audience: []const u8) !void {
        try self.setStringClaim(LABEL_AUD, audience);
    }

    /// Gets the audience claim
    pub fn getAudience(self: Claims) ?[]const u8 {
        return self.getStringClaim(LABEL_AUD);
    }

    /// Sets the expiration time claim
    pub fn setExpiration(self: *Claims, exp: i64) !void {
        try self.setIntClaim(LABEL_EXP, exp);
    }

    /// Gets the expiration time claim
    pub fn getExpiration(self: Claims) ?i64 {
        return self.getIntClaim(LABEL_EXP);
    }

    /// Sets the not before claim
    pub fn setNotBefore(self: *Claims, nbf: i64) !void {
        try self.setIntClaim(LABEL_NBF, nbf);
    }

    /// Gets the not before claim
    pub fn getNotBefore(self: Claims) ?i64 {
        return self.getIntClaim(LABEL_NBF);
    }

    /// Sets the issued at claim
    pub fn setIssuedAt(self: *Claims, iat: i64) !void {
        try self.setIntClaim(LABEL_IAT, iat);
    }

    /// Gets the issued at claim
    pub fn getIssuedAt(self: Claims) ?i64 {
        return self.getIntClaim(LABEL_IAT);
    }

    fn setBytesClaim(self: *Claims, label: u64, value: []const u8) !void {
        const dup = try self.allocator.dupe(u8, value);
        try self.claims.put(label, ClaimValue{ .Bytes = dup });
    }

    fn getBytesClaim(self: Claims, label: u64) ?[]const u8 {
        return if (self.claims.get(label)) |value| switch (value) {
            .Bytes => |bytes| bytes,
            else => null,
        } else null;
    }

    /// Sets the CWT ID claim
    pub fn setCwtId(self: *Claims, cti: []const u8) !void {
        try self.setBytesClaim(LABEL_CTI, cti);
    }

    /// Gets the CWT ID claim
    pub fn getCwtId(self: Claims) ?[]const u8 {
        return self.getBytesClaim(LABEL_CTI);
    }

    /// Sets the CAT version claim
    pub fn setCatVersion(self: *Claims, version: i64) !void {
        try self.setIntClaim(LABEL_CATV, version);
    }

    /// Gets the CAT version claim
    pub fn getCatVersion(self: Claims) ?i64 {
        return self.getIntClaim(LABEL_CATV);
    }

    /// Sets the CATREPLAY claim (0=permitted, 1=prohibited, 2=reuse-detection)
    pub fn setCatReplay(self: *Claims, mode: i64) !void {
        try self.setIntClaim(LABEL_CATREPLAY, mode);
    }

    /// Gets the CATREPLAY claim
    pub fn getCatReplay(self: Claims) ?i64 {
        return self.getIntClaim(LABEL_CATREPLAY);
    }

    /// Sets the CATPOR (Probability of Rejection) claim (0-100%)
    pub fn setCatPor(self: *Claims, probability: i64) !void {
        try self.setIntClaim(LABEL_CATPOR, probability);
    }

    /// Gets the CATPOR claim
    pub fn getCatPor(self: Claims) ?i64 {
        return self.getIntClaim(LABEL_CATPOR);
    }

    /// Sets the CATNIP (Network IP) claim with an array of IP addresses/ranges
    pub fn setCatNip(self: *Claims, ips: []const []const u8) !void {
        var array = ArrayList(ClaimValue){};
        for (ips) |ip| {
            const dup = try self.allocator.dupe(u8, ip);
            try array.append(self.allocator, ClaimValue{ .String = dup });
        }
        try self.setClaimOwned(LABEL_CATNIP, ClaimValue{ .Array = array });
    }

    /// Gets the CATNIP claim as an array of strings
    pub fn getCatNip(self: Claims) ?ArrayList(ClaimValue) {
        return if (self.claims.get(LABEL_CATNIP)) |value| switch (value) {
            .Array => |array| array,
            else => null,
        } else null;
    }

    /// Sets the CATM (HTTP Methods) claim with an array of allowed methods
    pub fn setCatM(self: *Claims, methods: []const []const u8) !void {
        var array = ArrayList(ClaimValue){};
        for (methods) |method| {
            const dup = try self.allocator.dupe(u8, method);
            try array.append(self.allocator, ClaimValue{ .String = dup });
        }
        try self.setClaimOwned(LABEL_CATM, ClaimValue{ .Array = array });
    }

    /// Gets the CATM claim as an array of strings
    pub fn getCatM(self: Claims) ?ArrayList(ClaimValue) {
        return if (self.claims.get(LABEL_CATM)) |value| switch (value) {
            .Array => |array| array,
            else => null,
        } else null;
    }

    /// Sets the CATALPN (TLS ALPN protocols) claim with an array of protocols
    pub fn setCatAlpn(self: *Claims, protocols: []const []const u8) !void {
        var array = ArrayList(ClaimValue){};
        for (protocols) |protocol| {
            const dup = try self.allocator.dupe(u8, protocol);
            try array.append(self.allocator, ClaimValue{ .String = dup });
        }
        try self.setClaimOwned(LABEL_CATALPN, ClaimValue{ .Array = array });
    }

    /// Gets the CATALPN claim as an array of strings
    pub fn getCatAlpn(self: Claims) ?ArrayList(ClaimValue) {
        return if (self.claims.get(LABEL_CATALPN)) |value| switch (value) {
            .Array => |array| array,
            else => null,
        } else null;
    }

    /// Sets the CATGEOISO3166 (country codes) claim with an array of ISO 3166 codes
    pub fn setCatGeoIso3166(self: *Claims, country_codes: []const []const u8) !void {
        var array = ArrayList(ClaimValue){};
        for (country_codes) |code| {
            const dup = try self.allocator.dupe(u8, code);
            try array.append(self.allocator, ClaimValue{ .String = dup });
        }
        try self.setClaimOwned(LABEL_CATGEOISO3166, ClaimValue{ .Array = array });
    }

    /// Gets the CATGEOISO3166 claim as an array of strings
    pub fn getCatGeoIso3166(self: Claims) ?ArrayList(ClaimValue) {
        return if (self.claims.get(LABEL_CATGEOISO3166)) |value| switch (value) {
            .Array => |array| array,
            else => null,
        } else null;
    }

    /// Sets a generic claim
    pub fn setClaim(self: *Claims, label: u64, value: ClaimValue) !void {
        if (self.claims.getPtr(label)) |old_value| {
            var old_val = old_value.*;
            old_val.deinit(self.allocator);
        }
        try self.claims.put(label, try value.clone(self.allocator));
    }

    /// Takes ownership of the value without cloning
    fn setClaimOwned(self: *Claims, label: u64, value: ClaimValue) !void {
        if (self.claims.getPtr(label)) |old_value| {
            var old_val = old_value.*;
            old_val.deinit(self.allocator);
        }
        try self.claims.put(label, value);
    }

    /// Gets a generic claim
    pub fn getClaim(self: Claims, label: u64) ?ClaimValue {
        return self.claims.get(label);
    }

    fn encodeClaimValue(encoder: *zbor.Encoder, value: ClaimValue) !void {
        switch (value) {
            .String => |str| try encoder.pushText(str),
            .Integer => |int| try encoder.pushInt(int),
            .Bytes => |bytes| try encoder.pushBytes(bytes),
            .Array => |array| {
                try encoder.beginArray(@intCast(array.items.len));
                for (array.items) |item| {
                    try encodeClaimValue(encoder, item);
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
                    try encodeClaimValue(encoder, map_value);
                }
                try encoder.endMap();
            },
        }
    }

    /// Serializes the claims to CBOR
    pub fn toCbor(self: Claims, allocator: Allocator) ![]u8 {
        var encoder = zbor.Encoder.init(allocator);
        defer encoder.deinit();

        try encoder.beginMap(@intCast(self.claims.count()));

        var it = self.claims.iterator();
        while (it.next()) |entry| {
            const label = entry.key_ptr.*;
            const value = entry.value_ptr.*;

            try encoder.pushInt(label);
            try encodeClaimValue(&encoder, value);
        }

        try encoder.endMap();
        return allocator.dupe(u8, encoder.finish());
    }

    /// Deserializes claims from CBOR
    pub fn fromCbor(allocator: Allocator, cbor_data: []const u8) !Claims {
        var claims = Claims.init(allocator);
        errdefer claims.deinit();

        var decoder = zbor.Decoder.init(cbor_data, allocator);
        defer decoder.deinit();

        const map_len = try decoder.beginMap();

        var i: usize = 0;
        while (i < map_len) : (i += 1) {
            const label = try decoder.readInt(u64);
            const major_type = try decoder.peekMajorType();

            switch (major_type) {
                .TextString => {
                    const str = try decoder.readText(allocator);
                    try claims.setClaimOwned(label, ClaimValue{ .String = str });
                },
                .UnsignedInt, .NegativeInt => {
                    const int = try decoder.readInt(i64);
                    try claims.setClaimOwned(label, ClaimValue{ .Integer = int });
                },
                .ByteString => {
                    const bytes = try decoder.readBytes(allocator);
                    try claims.setClaimOwned(label, ClaimValue{ .Bytes = bytes });
                },
                .Array => {
                    const array_len = try decoder.beginArray();
                    var array = ArrayList(ClaimValue){};
                    errdefer {
                        for (array.items) |*item| {
                            item.deinit(allocator);
                        }
                        array.deinit(allocator);
                    }

                    var j: usize = 0;
                    while (j < array_len) : (j += 1) {
                        const item_major_type = try decoder.peekMajorType();

                        switch (item_major_type) {
                            .TextString => {
                                const str = try decoder.readText(allocator);
                                try array.append(allocator, ClaimValue{ .String = str });
                            },
                            .UnsignedInt, .NegativeInt => {
                                const int = try decoder.readInt(i64);
                                try array.append(allocator, ClaimValue{ .Integer = int });
                            },
                            .ByteString => {
                                const bytes = try decoder.readBytes(allocator);
                                try array.append(allocator, ClaimValue{ .Bytes = bytes });
                            },
                            else => return Error.CborDecodingError,
                        }
                    }

                    try decoder.endArray();
                    try claims.setClaimOwned(label, ClaimValue{ .Array = array });
                },
                .Map => {
                    const map_len2 = try decoder.beginMap();
                    var map = AutoHashMap(u64, ClaimValue).init(allocator);
                    errdefer {
                        var map_it = map.iterator();
                        while (map_it.next()) |map_entry| {
                            var map_value = map_entry.value_ptr.*;
                            map_value.deinit(allocator);
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
                    try claims.setClaimOwned(label, ClaimValue{ .Map = map });
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
