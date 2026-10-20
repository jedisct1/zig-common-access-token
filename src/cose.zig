const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const crypto = std.crypto;
const testing = std.testing;

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

const Error = @import("error.zig").Error;
const zbor = @import("zbor.zig");

pub const ALG_HS256: i64 = 5;
pub const HEADER_ALG: i64 = 1;
pub const HEADER_CRIT: i64 = 2;
pub const HEADER_KID: i64 = 4;
pub const TAG_COSE_MAC0: u64 = 17;
pub const TAG_CWT: u64 = 61;

/// The only COSE header parameters needed to verify a token
pub const Header = struct {
    alg: ?i64 = null,
    kid: ?[]const u8 = null,
};

pub fn readHeader(allocator: Allocator, decoder: *zbor.Decoder) !Header {
    var header: Header = .{};
    var items = try decoder.mapItems();
    while (try items.next(decoder)) {
        // Text labels are private parameters, which we don't use.
        if (try decoder.peekMajorType() == .TextString) {
            try decoder.skip();
            try decoder.skip();
            continue;
        }
        switch (try decoder.readInt(i64)) {
            HEADER_ALG => header.alg = try decoder.readInt(i64),
            // Core parameters never go in crit, so it always names an extension that we don't support.
            HEADER_CRIT => return Error.InvalidTokenHeader,
            // The key ID should be a byte string, but some implementations send text.
            HEADER_KID => header.kid = switch (try decoder.peekMajorType()) {
                .ByteString => try decoder.readBytes(allocator),
                .TextString => try decoder.readText(allocator),
                else => return Error.InvalidTokenHeader,
            },
            else => try decoder.skip(),
        }
    }
    return header;
}

/// Verifies a COSE_Mac0 tag. `protected` must be the header bytes as received, since that's what the MAC covers.
pub fn verifyTag(allocator: Allocator, protected: []const u8, payload: []const u8, tag: []const u8, key: []const u8) !void {
    if (tag.len != HmacSha256.mac_length) return Error.TagMismatch;
    const expected_tag = try computeTag(allocator, protected, payload, key);
    if (!crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected_tag, tag[0..HmacSha256.mac_length].*)) {
        return Error.TagMismatch;
    }
}

fn computeTag(allocator: Allocator, protected: []const u8, payload: []const u8, key: []const u8) ![HmacSha256.mac_length]u8 {
    var mac_structure = try zbor.Encoder.init(allocator);
    defer mac_structure.deinit();
    try mac_structure.beginArray(4);
    try mac_structure.pushText("MAC0");
    try mac_structure.pushBytes(protected);
    try mac_structure.pushBytes("");
    try mac_structure.pushBytes(payload);

    var tag: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&tag, mac_structure.finish(), key);
    return tag;
}

/// COSE_Mac0 structure as defined in RFC 8152 Section 6.2.
///
/// This structure represents a MAC-protected message with a single recipient.
/// It consists of:
/// - Protected header: Cryptographically protected parameters
/// - Unprotected header: Parameters not cryptographically protected
/// - Payload: The content being protected
/// - Tag: The authentication tag
pub const CoseMac0 = struct {
    allocator: Allocator,
    protected_header: AutoHashMap(i64, []const u8),
    unprotected_header: AutoHashMap(i64, []const u8),
    payload: []const u8,
    tag: []const u8,

    /// Creates a new COSE_Mac0 structure.
    pub fn init(
        allocator: Allocator,
        protected_header: AutoHashMap(i64, []const u8),
        unprotected_header: AutoHashMap(i64, []const u8),
        payload: []const u8,
    ) CoseMac0 {
        return CoseMac0{
            .allocator = allocator,
            .protected_header = protected_header,
            .unprotected_header = unprotected_header,
            .payload = payload,
            .tag = &[_]u8{},
        };
    }

    /// Frees memory associated with the COSE_Mac0 structure.
    /// Note: Payload and tag are not freed as they may be owned by the caller.
    pub fn deinit(self: *CoseMac0) void {
        self.protected_header.deinit();
        self.unprotected_header.deinit();
    }

    /// Creates an authentication tag for the COSE_Mac0 structure.
    pub fn createTag(self: *CoseMac0, key: []const u8) !void {
        const protected_header_cbor = try serializeCbor(self.allocator, self.protected_header);
        defer self.allocator.free(protected_header_cbor);

        const tag = try computeTag(self.allocator, protected_header_cbor, self.payload, key);
        self.tag = try self.allocator.dupe(u8, &tag);
    }

    /// Verifies the authentication tag of the COSE_Mac0 structure.
    pub fn verify(self: *const CoseMac0, key: []const u8) !void {
        const protected_header_cbor = try serializeCbor(self.allocator, self.protected_header);
        defer self.allocator.free(protected_header_cbor);

        try verifyTag(self.allocator, protected_header_cbor, self.payload, self.tag, key);
    }

    /// Serializes the COSE_Mac0 structure to CBOR
    pub fn toCbor(self: *const CoseMac0, out: *std.ArrayList(u8)) !void {
        const protected_header_cbor = try serializeCbor(self.allocator, self.protected_header);
        defer self.allocator.free(protected_header_cbor);

        const unprotected_header_cbor = try serializeCbor(self.allocator, self.unprotected_header);
        defer self.allocator.free(unprotected_header_cbor);

        try serializeCoseMac0(
            self.allocator,
            protected_header_cbor,
            unprotected_header_cbor,
            self.payload,
            self.tag,
            out,
        );
    }

    /// Gets the payload of the COSE_Mac0 structure.
    pub fn getPayload(self: *const CoseMac0) []const u8 {
        return self.payload;
    }
};

fn serializeCbor(allocator: Allocator, map: AutoHashMap(i64, []const u8)) ![]u8 {
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.beginMap(@intCast(map.count()));

    var it = map.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        try encoder.pushInt(key);

        if (key == HEADER_ALG) {
            const alg_int = try std.fmt.parseInt(i64, value, 10);
            try encoder.pushInt(alg_int);
        } else {
            try encoder.pushBytes(value);
        }
    }

    try encoder.endMap();
    return allocator.dupe(u8, encoder.finish());
}

fn serializeCoseMac0(
    allocator: Allocator,
    protected: []const u8,
    unprotected: []const u8,
    payload: []const u8,
    tag: []const u8,
    out: *std.ArrayList(u8),
) !void {
    var encoder = try zbor.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.beginArray(4);
    try encoder.pushBytes(protected);
    try encoder.pushRaw(unprotected);
    try encoder.pushBytes(payload);
    try encoder.pushBytes(tag);
    try encoder.endArray();

    try out.appendSlice(allocator, encoder.finish());
}

test "COSE_Mac0 basic operations" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const protected_header = AutoHashMap(i64, []const u8).init(allocator);
    const unprotected_header = AutoHashMap(i64, []const u8).init(allocator);

    var cose_mac0 = CoseMac0.init(
        allocator,
        protected_header,
        unprotected_header,
        "payload",
    );
    defer cose_mac0.deinit();

    try cose_mac0.createTag("key");
    try cose_mac0.verify("key");

    var cbor = std.ArrayList(u8).empty;
    defer cbor.deinit(allocator);

    try cose_mac0.toCbor(&cbor);
    try testing.expect(cbor.items.len > 0);
}
