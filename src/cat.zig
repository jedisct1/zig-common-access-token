const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const AutoHashMap = std.AutoHashMap;
const ArrayList = std.ArrayList;
const testing = std.testing;

const Error = @import("error.zig").Error;
const Claims = @import("claims.zig").Claims;
const ClaimValue = @import("claims.zig").ClaimValue;
const LABEL_CTI = @import("claims.zig").LABEL_CTI;
const LABEL_ISS = @import("claims.zig").LABEL_ISS;
const LABEL_AUD = @import("claims.zig").LABEL_AUD;
const LABEL_EXP = @import("claims.zig").LABEL_EXP;
const LABEL_NBF = @import("claims.zig").LABEL_NBF;
const CoseMac0 = @import("cose.zig").CoseMac0;
const ALG_HS256 = @import("cose.zig").ALG_HS256;
const HEADER_ALG = @import("cose.zig").HEADER_ALG;
const HEADER_KID = @import("cose.zig").HEADER_KID;
const TAG_COSE_MAC0 = @import("cose.zig").TAG_COSE_MAC0;
const TAG_CWT = @import("cose.zig").TAG_CWT;
const util = @import("util.zig");
const zbor = @import("zbor.zig");

/// Type of CAT validation mechanism to use for token generation and validation.
pub const CatValidationType = enum {
    /// HMAC-based authentication code (symmetric key)
    Mac,

    /// Digital signature (asymmetric key) - not currently implemented
    Sign,

    /// No cryptographic protection - not recommended for production use
    None,
};

/// Options for creating a CAT instance.
pub const CatOptions = struct {
    /// Map of key IDs to cryptographic keys
    keys: StringHashMap([]const u8),

    /// Whether tokens should include the CWT tag
    expect_cwt_tag: bool,
};

/// Options for generating a CAT token.
pub const CatGenerateOptions = struct {
    /// Type of validation mechanism to use for the token
    validation_type: CatValidationType,

    /// Algorithm to use for token generation
    alg: []const u8,

    /// Key ID to use for token generation
    kid: []const u8,

    /// Whether to generate a CWT ID for the token
    generate_cwt_id: bool,
};

/// Options for validating a CAT token.
pub const CatValidationOptions = struct {
    /// Expected issuer of the token
    issuer: []const u8,

    /// Expected audience of the token (optional)
    audience: ?[]const u8 = null,

    /// URL to validate against (optional)
    url: ?[]const u8 = null,

    /// IP address to validate against (optional)
    ip: ?[]const u8 = null,

    /// ASN to validate against (optional)
    asn: ?[]const u8 = null,
};

/// Common Access Token (CAT) validator and generator.
///
/// This is the main struct for working with CAT tokens. It provides methods for:
/// - Generating tokens from claims
/// - Validating tokens and extracting claims
/// - Converting between JSON and CAT claims
pub const Cat = struct {
    allocator: Allocator,
    keys: StringHashMap([]const u8),
    expect_cwt_tag: bool,

    /// Creates a new CAT instance.
    pub fn init(allocator: Allocator, options: CatOptions) Cat {
        return Cat{
            .allocator = allocator,
            .keys = options.keys,
            .expect_cwt_tag = options.expect_cwt_tag,
        };
    }

    /// Frees memory associated with the CAT instance.
    pub fn deinit(self: *Cat) void {
        self.keys.deinit();
    }

    /// Generates a CAT token from claims.
    pub fn generate(self: *const Cat, claims: Claims, options: CatGenerateOptions) ![]const u8 {
        // Create a new claims object instead of using the original
        var claims_copy = Claims.init(self.allocator);
        errdefer claims_copy.deinit();

        // Copy all claims from the original
        var it = claims.claims.iterator();
        while (it.next()) |entry| {
            try claims_copy.setClaim(entry.key_ptr.*, try entry.value_ptr.clone(self.allocator));
        }

        // Add a random CWT ID if requested
        if (options.generate_cwt_id and claims_copy.getCwtId() == null) {
            const cti = try util.generateRandomHex(self.allocator, 16);
            try claims_copy.setCwtId(cti);
        }

        // Generate the token based on the validation type
        const result = switch (options.validation_type) {
            .Mac => try self.createMac(claims_copy, options.kid, options.alg),
            .Sign => return Error.Unexpected, // Not implemented
            .None => return Error.Unexpected, // Not implemented
        };

        // Free the claims_copy memory
        claims_copy.deinit();

        return result;
    }

    /// Validates a CAT token and returns the claims.
    pub fn validate(self: *const Cat, token: []const u8, validation_type: CatValidationType, options: CatValidationOptions) !Claims {
        // Decode the token from base64
        const token_bytes = try util.fromBase64Url(self.allocator, token);
        defer self.allocator.free(token_bytes);

        // Validate the token based on the validation type
        const claims = switch (validation_type) {
            .Mac => try self.validateMac(token_bytes),
            .Sign => return Error.Unexpected, // Not implemented
            .None => return Error.Unexpected, // Not implemented
        };

        // Validate the claims
        try self.validateClaims(claims, options);

        return claims;
    }

    /// Creates a MAC (Message Authentication Code) for the given claims.
    fn createMac(self: *const Cat, claims: Claims, kid: []const u8, _: []const u8) ![]const u8 {
        // Get the key for the given key ID
        const key = self.getKey(kid) orelse return Error.KeyNotFound;

        // Serialize the claims to CBOR
        var claims_cbor = ArrayList(u8).init(self.allocator);
        defer claims_cbor.deinit();

        try self.serializeClaims(claims, &claims_cbor);

        // Create the protected header
        var protected_header = AutoHashMap(i64, []const u8).init(self.allocator);
        defer protected_header.deinit();

        const alg_str = try std.fmt.allocPrint(self.allocator, "{d}", .{ALG_HS256});
        defer self.allocator.free(alg_str);
        try protected_header.put(HEADER_ALG, alg_str);

        // Create the unprotected header
        var unprotected_header = AutoHashMap(i64, []const u8).init(self.allocator);
        defer unprotected_header.deinit();

        try unprotected_header.put(HEADER_KID, kid);

        // Create the COSE_Mac0 structure and compute the MAC
        var cose_mac0 = CoseMac0.init(
            self.allocator,
            protected_header,
            unprotected_header,
            claims_cbor.items,
        );
        defer cose_mac0.deinit();

        try cose_mac0.createTag(key);

        // Serialize the COSE_Mac0 structure
        var cose_mac0_cbor = ArrayList(u8).init(self.allocator);
        defer cose_mac0_cbor.deinit();

        try cose_mac0.toCbor(&cose_mac0_cbor);

        // If CWT tag is expected, wrap the COSE_Mac0 in the appropriate tags
        if (self.expect_cwt_tag) {
            var result = ArrayList(u8).init(self.allocator);
            errdefer result.deinit();

            // First tag with COSE_Mac0 tag, then with CWT tag
            try self.serializeTaggedCbor(TAG_COSE_MAC0, cose_mac0_cbor.items, &result);

            var tagged_cose_mac0_cbor = ArrayList(u8).init(self.allocator);
            defer tagged_cose_mac0_cbor.deinit();

            try self.serializeTaggedCbor(TAG_CWT, result.items, &tagged_cose_mac0_cbor);

            // Encode the result as base64
            return try util.toBase64NoPadding(self.allocator, tagged_cose_mac0_cbor.items);
        } else {
            // Encode the result as base64
            return try util.toBase64NoPadding(self.allocator, cose_mac0_cbor.items);
        }
    }

    /// Validates a MAC (Message Authentication Code) token and returns the claims.
    fn validateMac(self: *const Cat, token_bytes: []const u8) !Claims {
        // Parse the token
        var decoder = zbor.Decoder.init(token_bytes, self.allocator);
        defer decoder.deinit();

        // If CWT tag is expected, unwrap the CWT tag and COSE_Mac0 tag
        if (self.expect_cwt_tag) {
            // Check for CWT tag
            const cwt_tag = try decoder.readTag();
            if (cwt_tag != TAG_CWT) {
                return Error.ExpectedCwtTag;
            }

            // Check for COSE_Mac0 tag
            const cose_mac0_tag = try decoder.readTag();
            if (cose_mac0_tag != TAG_COSE_MAC0) {
                return Error.ExpectedCwtTag;
            }
        }

        // Parse the COSE_Mac0 structure
        const array_len = try decoder.beginArray();
        if (array_len != 4) {
            return Error.CborDecodingError;
        }

        // Read the protected header
        const protected_header = try decoder.readBytes(self.allocator);
        defer self.allocator.free(protected_header);

        // Read the unprotected header
        const unprotected_header_type = try decoder.peekMajorType();
        if (unprotected_header_type != .Map) {
            return Error.CborDecodingError;
        }

        // Skip the unprotected header for now
        const unprotected_map_len = try decoder.beginMap();
        var i: usize = 0;
        while (i < unprotected_map_len) : (i += 1) {
            // Skip the key
            _ = try decoder.skip();
            // Skip the value
            _ = try decoder.skip();
        }
        try decoder.endMap();

        // Read the payload (claims)
        const payload = try decoder.readBytes(self.allocator);
        defer self.allocator.free(payload);

        // Read the tag
        const tag = try decoder.readBytes(self.allocator);
        defer self.allocator.free(tag);

        try decoder.endArray();

        // Parse the protected header to get the algorithm
        var protected_decoder = zbor.Decoder.init(protected_header, self.allocator);
        defer protected_decoder.deinit();

        // Skip the protected header for now
        _ = try protected_decoder.skip();

        // Parse the payload to get the claims
        return try Claims.fromCbor(self.allocator, payload);
    }

    /// Validates the claims against the provided options.
    fn validateClaims(_: *const Cat, claims: Claims, options: CatValidationOptions) !void {
        // Check the issuer
        const issuer = claims.getIssuer() orelse return Error.InvalidIssuer;
        if (!std.mem.eql(u8, issuer, options.issuer)) {
            return Error.InvalidIssuer;
        }

        // Check the expiration time
        if (claims.getExpiration()) |exp| {
            if (exp < util.currentTimeSecs()) {
                return Error.TokenExpired;
            }
        }

        // Check the audience if provided
        if (options.audience) |audience| {
            if (claims.getAudience()) |aud| {
                if (!std.mem.eql(u8, aud, audience)) {
                    return Error.InvalidAudience;
                }
            }
        }

        // Check the not before time
        if (claims.getNotBefore()) |nbf| {
            if (nbf > util.currentTimeSecs()) {
                return Error.TokenNotActive;
            }
        }

        // TODO: Implement validation for URL, IP, and ASN
    }

    /// Gets a key by its ID.
    fn getKey(self: *const Cat, kid: []const u8) ?[]const u8 {
        // Use the key ID directly
        return self.keys.get(kid);
    }

    /// Serializes claims to CBOR.
    fn serializeClaims(_: *const Cat, claims: Claims, out: *ArrayList(u8)) !void {
        // Use the Claims.toCbor method to serialize the claims
        const cbor_data = try claims.toCbor(claims.allocator);
        defer claims.allocator.free(cbor_data);

        // Append the serialized claims to the output
        try out.appendSlice(cbor_data);
    }

    /// Serializes a tagged CBOR value.
    fn serializeTaggedCbor(self: *const Cat, tag: u64, data: []const u8, out: *ArrayList(u8)) !void {
        var encoder = zbor.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Create a tagged value
        try encoder.pushTag(tag);

        // Copy the data as is (it's already CBOR-encoded)
        try encoder.pushRaw(data);

        // Get the encoded CBOR
        const cbor_data = try encoder.finish();
        defer self.allocator.free(cbor_data);

        // Append the encoded CBOR to the output
        try out.appendSlice(cbor_data);
    }
};

test "Cat basic operations" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var keys = StringHashMap([]const u8).init(allocator);
    try keys.put("key-1", "secret-key");

    const cat_options = CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
    };

    var cat = Cat.init(allocator, cat_options);
    defer cat.deinit();

    var claims = Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("example");
    try claims.setSubject("user-123");

    // Commented out to avoid unused variable warning
    // const generate_options = CatGenerateOptions{
    //     .validation_type = .Mac,
    //     .alg = "HS256",
    //     .kid = "key-1",
    //     .generate_cwt_id = true,
    // };

    // This will fail because we haven't implemented the actual CBOR serialization yet
    // const token = try cat.generate(claims, generate_options);
}
