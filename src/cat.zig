const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const AutoHashMap = std.AutoHashMap;
const ArrayList = std.ArrayList;
const testing = std.testing;

const Error = @import("error.zig").Error;
const Claims = @import("claims.zig").Claims;
const ClaimValue = @import("claims.zig").ClaimValue;
const FingerprintType = @import("claims.zig").FingerprintType;
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
const validation = @import("validation.zig");

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

    /// HTTP method to validate against CATM claim (optional)
    http_method: ?[]const u8 = null,

    /// Whether token has been seen before for CATREPLAY validation (default: false)
    token_seen_before: bool = false,

    /// TLS fingerprint type to validate against CATTPRINT claim (optional)
    fingerprint_type: ?FingerprintType = null,

    /// TLS fingerprint value to validate against CATTPRINT claim (optional)
    fingerprint_value: ?[]const u8 = null,
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
    /// Note: The keys hashmap is not owned by Cat and should be freed by the caller.
    pub fn deinit(self: *Cat) void {
        _ = self;
    }

    /// Generates a CAT token from claims
    pub fn generate(self: *const Cat, claims: Claims, options: CatGenerateOptions) ![]const u8 {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

        var claims_copy = Claims.init(temp_allocator);
        var it = claims.claims.iterator();
        while (it.next()) |entry| {
            try claims_copy.setClaim(entry.key_ptr.*, entry.value_ptr.*);
        }

        if (options.generate_cwt_id and claims_copy.getCwtId() == null) {
            const cti = try util.generateRandomHex(temp_allocator, 16);
            try claims_copy.setCwtId(cti);
        }

        return switch (options.validation_type) {
            .Mac => try self.createMac(temp_allocator, claims_copy, options.kid, options.alg),
            .Sign => return Error.Unexpected,
            .None => return Error.Unexpected,
        };
    }

    /// Validates a CAT token and returns the claims
    pub fn validate(self: *const Cat, token: []const u8, validation_type: CatValidationType, options: CatValidationOptions) !Claims {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

        const token_bytes = try util.fromBase64Url(temp_allocator, token);

        var claims = switch (validation_type) {
            .Mac => try self.validateMac(temp_allocator, token_bytes),
            .Sign => return Error.Unexpected,
            .None => return Error.Unexpected,
        };
        errdefer claims.deinit();

        try self.validateClaims(claims, options);
        return claims;
    }

    fn createMac(self: *const Cat, temp_allocator: Allocator, claims: Claims, kid: []const u8, _: []const u8) ![]const u8 {
        const key = self.getKey(kid) orelse return Error.KeyNotFound;
        const claims_cbor = try claims.toCbor(temp_allocator);

        var protected_header = AutoHashMap(i64, []const u8).init(temp_allocator);
        const alg_str = try std.fmt.allocPrint(temp_allocator, "{d}", .{ALG_HS256});
        try protected_header.put(HEADER_ALG, alg_str);

        var unprotected_header = AutoHashMap(i64, []const u8).init(temp_allocator);
        try unprotected_header.put(HEADER_KID, kid);

        var cose_mac0 = CoseMac0.init(temp_allocator, protected_header, unprotected_header, claims_cbor);
        try cose_mac0.createTag(key);

        var cose_mac0_cbor = ArrayList(u8){};
        defer cose_mac0_cbor.deinit(temp_allocator);
        try cose_mac0.toCbor(&cose_mac0_cbor);

        if (self.expect_cwt_tag) {
            var result = ArrayList(u8){};
            defer result.deinit(temp_allocator);
            try self.serializeTaggedCbor(temp_allocator, TAG_COSE_MAC0, cose_mac0_cbor.items, &result);

            var tagged_cose_mac0_cbor = ArrayList(u8){};
            defer tagged_cose_mac0_cbor.deinit(temp_allocator);
            try self.serializeTaggedCbor(temp_allocator, TAG_CWT, result.items, &tagged_cose_mac0_cbor);

            return try util.toBase64NoPadding(self.allocator, tagged_cose_mac0_cbor.items);
        } else {
            return try util.toBase64NoPadding(self.allocator, cose_mac0_cbor.items);
        }
    }

    fn validateMac(self: *const Cat, temp_allocator: Allocator, token_bytes: []const u8) !Claims {
        var decoder = zbor.Decoder.init(token_bytes, temp_allocator);
        defer decoder.deinit();

        if (self.expect_cwt_tag) {
            const cwt_tag = try decoder.readTag();
            if (cwt_tag != TAG_CWT) return Error.ExpectedCwtTag;

            const cose_mac0_tag = try decoder.readTag();
            if (cose_mac0_tag != TAG_COSE_MAC0) return Error.ExpectedCwtTag;
        }

        const array_len = try decoder.beginArray();
        if (array_len != 4) return Error.CborDecodingError;

        const protected_header = try decoder.readBytes(temp_allocator);

        const unprotected_header_type = try decoder.peekMajorType();
        if (unprotected_header_type != .Map) return Error.CborDecodingError;

        const unprotected_map_len = try decoder.beginMap();
        var i: usize = 0;
        while (i < unprotected_map_len) : (i += 1) {
            _ = try decoder.skip();
            _ = try decoder.skip();
        }
        try decoder.endMap();

        const payload = try decoder.readBytes(temp_allocator);
        const tag = try decoder.readBytes(temp_allocator);
        _ = tag;

        try decoder.endArray();

        var protected_decoder = zbor.Decoder.init(protected_header, temp_allocator);
        defer protected_decoder.deinit();
        _ = try protected_decoder.skip();

        return try Claims.fromCbor(self.allocator, payload);
    }

    fn validateClaims(self: *const Cat, claims: Claims, options: CatValidationOptions) !void {
        const issuer = claims.getIssuer() orelse return Error.InvalidIssuer;
        if (!std.mem.eql(u8, issuer, options.issuer)) return Error.InvalidIssuer;

        if (claims.getExpiration()) |exp| {
            if (exp < util.currentTimeSecs()) return Error.TokenExpired;
        }

        if (options.audience) |audience| {
            if (claims.getAudience()) |aud| {
                if (!std.mem.eql(u8, aud, audience)) return Error.InvalidAudience;
            }
        }

        if (claims.getNotBefore()) |nbf| {
            if (nbf > util.currentTimeSecs()) return Error.TokenNotActive;
        }

        // Validate CATU (URI) claim if URL is provided
        if (options.url) |url| {
            try validation.validateCatu(self.allocator, claims, url);
        }

        // Validate CATM (HTTP method) claim if method is provided
        if (options.http_method) |method| {
            try validation.validateCatm(claims, method);
        }

        // Validate CATREPLAY claim
        try validation.validateCatreplay(claims, options.token_seen_before);

        // Validate CATTPRINT (TLS Fingerprint) claim if fingerprint type and value are provided
        if (options.fingerprint_type) |ftype| {
            if (options.fingerprint_value) |fvalue| {
                try validation.validateCattprint(self.allocator, claims, ftype, fvalue);
            }
        }

        _ = options.ip;
        _ = options.asn;
    }

    fn getKey(self: *const Cat, kid: []const u8) ?[]const u8 {
        return self.keys.get(kid);
    }

    fn serializeTaggedCbor(_: *const Cat, allocator: Allocator, tag: u64, data: []const u8, out: *ArrayList(u8)) !void {
        var encoder = try zbor.Encoder.init(allocator);
        defer encoder.deinit();
        try encoder.pushTag(tag);
        try encoder.pushRaw(data);
        try out.appendSlice(allocator, encoder.finish());
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
}
