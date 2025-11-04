const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const crypto = std.crypto;
const testing = std.testing;

const Error = @import("error.zig").Error;
const zbor = @import("zbor.zig");

// COSE algorithm identifiers
pub const ALG_HS256: i64 = 5; // HMAC 256-bit SHA-256

// COSE header parameters
pub const HEADER_ALG: i64 = 1; // Algorithm
pub const HEADER_KID: i64 = 4; // Key ID

// COSE tags
pub const TAG_COSE_MAC0: u64 = 17; // COSE_Mac0 tag
pub const TAG_CWT: u64 = 61; // CWT tag

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

    /// Frees memory associated with the COSE_Mac0 structure
    pub fn deinit(self: *CoseMac0) void {
        self.protected_header.deinit();
        self.unprotected_header.deinit();
        // Payload and tag are not freed here as they might be owned by the caller
    }

    /// Creates an authentication tag for the COSE_Mac0 structure.
    ///
    /// This method computes an HMAC-SHA256 tag over the MAC_structure as defined
    /// in RFC 8152 Section 6.3. The MAC_structure includes:
    /// - The context string "MAC0"
    /// - The protected header
    /// - The external AAD (empty in this implementation)
    /// - The payload
    pub fn createTag(self: *CoseMac0, key: []const u8) !void {
        // Serialize the protected header to CBOR
        var protected_header_cbor = std.ArrayList(u8){};
        defer protected_header_cbor.deinit(self.allocator);

        try serializeCbor(self.allocator, self.protected_header, &protected_header_cbor);

        // Create the MAC_structure as defined in RFC 8152 Section 6.3
        // MAC_structure = [
        //   context: "MAC0",
        //   protected: bstr,
        //   external_aad: bstr,
        //   payload: bstr
        // ]
        var mac_structure = std.ArrayList(u8){};
        defer mac_structure.deinit(self.allocator);

        // Serialize the MAC_structure to CBOR
        try serializeMacStructure(
            self.allocator,
            "MAC0",
            protected_header_cbor.items,
            &[_]u8{}, // empty external_aad
            self.payload,
            &mac_structure,
        );

        // Compute the HMAC
        var tag_buf: [crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
        crypto.auth.hmac.sha2.HmacSha256.create(&tag_buf, mac_structure.items, key);

        // Store the tag
        self.tag = try self.allocator.dupe(u8, &tag_buf);
    }

    /// Verifies the authentication tag of the COSE_Mac0 structure.
    pub fn verify(self: *const CoseMac0, key: []const u8) !void {
        // Serialize the protected header to CBOR
        var protected_header_cbor = std.ArrayList(u8){};
        defer protected_header_cbor.deinit(self.allocator);

        try serializeCbor(self.allocator, self.protected_header, &protected_header_cbor);

        // Create the MAC_structure
        var mac_structure = std.ArrayList(u8){};
        defer mac_structure.deinit(self.allocator);

        try serializeMacStructure(
            self.allocator,
            "MAC0",
            protected_header_cbor.items,
            &[_]u8{}, // empty external_aad
            self.payload,
            &mac_structure,
        );

        // Compute and verify the HMAC
        var expected_tag: [crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
        crypto.auth.hmac.sha2.HmacSha256.create(&expected_tag, mac_structure.items, key);

        if (!crypto.timing_safe.eql(u8, &expected_tag, self.tag)) {
            return Error.TagMismatch;
        }
    }

    /// Serializes the COSE_Mac0 structure to CBOR.
    pub fn toCbor(self: *const CoseMac0, out: *std.ArrayList(u8)) !void {
        // COSE_Mac0 = [
        //   protected: bstr,
        //   unprotected: map,
        //   payload: bstr,
        //   tag: bstr
        // ]

        // Serialize the protected header to CBOR
        var protected_header_cbor = std.ArrayList(u8){};
        defer protected_header_cbor.deinit(self.allocator);

        try serializeCbor(self.allocator, self.protected_header, &protected_header_cbor);

        // Serialize the unprotected header to CBOR
        var unprotected_header_cbor = std.ArrayList(u8){};
        defer unprotected_header_cbor.deinit(self.allocator);

        try serializeCbor(self.allocator, self.unprotected_header, &unprotected_header_cbor);

        // Serialize the COSE_Mac0 structure
        try serializeCoseMac0(
            self.allocator,
            protected_header_cbor.items,
            unprotected_header_cbor.items,
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

/// Serializes a CBOR map to a byte array.
fn serializeCbor(
    allocator: Allocator,
    map: AutoHashMap(i64, []const u8),
    out: *std.ArrayList(u8),
) !void {
    var encoder = zbor.Encoder.init(allocator);
    defer encoder.deinit();

    // Start a map with the number of entries
    try encoder.beginMap(@intCast(map.count()));

    // Add each entry to the map
    var it = map.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        // Add the key as an integer
        try encoder.pushInt(key);

        // Add the value as a byte string
        try encoder.pushBytes(value);
    }

    // End the map
    try encoder.endMap();

    // Get the encoded CBOR
    const cbor_data = try encoder.finish();
    defer allocator.free(cbor_data);

    // Append the encoded CBOR to the output
    try out.appendSlice(allocator, cbor_data);
}

/// Serializes a MAC_structure to CBOR.
fn serializeMacStructure(
    allocator: Allocator,
    context: []const u8,
    protected: []const u8,
    external_aad: []const u8,
    payload: []const u8,
    out: *std.ArrayList(u8),
) !void {
    var encoder = zbor.Encoder.init(allocator);
    defer encoder.deinit();

    // Start an array with 4 items
    try encoder.beginArray(4);

    // Context
    try encoder.pushText(context);

    // Protected
    try encoder.pushBytes(protected);

    // External AAD
    try encoder.pushBytes(external_aad);

    // Payload
    try encoder.pushBytes(payload);

    // End the array
    try encoder.endArray();

    // Get the encoded CBOR
    const cbor_data = try encoder.finish();
    defer allocator.free(cbor_data);

    // Append the encoded CBOR to the output
    try out.appendSlice(allocator, cbor_data);
}

/// Serializes a COSE_Mac0 structure to CBOR.
fn serializeCoseMac0(
    allocator: Allocator,
    protected: []const u8,
    unprotected: []const u8,
    payload: []const u8,
    tag: []const u8,
    out: *std.ArrayList(u8),
) !void {
    var encoder = zbor.Encoder.init(allocator);
    defer encoder.deinit();

    // Start an array with 4 items
    try encoder.beginArray(4);

    // Protected
    try encoder.pushBytes(protected);

    // Unprotected
    // Parse the unprotected header from CBOR
    var decoder = zbor.Decoder.init(unprotected, allocator);
    defer decoder.deinit();

    // Copy the unprotected header to the output
    try encoder.pushBytes(unprotected);

    // Payload
    try encoder.pushBytes(payload);

    // Tag
    try encoder.pushBytes(tag);

    // End the array
    try encoder.endArray();

    // Get the encoded CBOR
    const cbor_data = try encoder.finish();
    defer allocator.free(cbor_data);

    // Append the encoded CBOR to the output
    try out.appendSlice(allocator, cbor_data);
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

    var cbor = std.ArrayList(u8){};
    defer cbor.deinit(allocator);

    try cose_mac0.toCbor(&cbor);
    try testing.expect(cbor.items.len > 0);
}
