const std = @import("std");

/// Errors that can occur during CAT token operations.
///
/// This enum represents all the possible errors that can occur when
/// generating, validating, or processing CAT tokens.
pub const Error = error{
    // CBOR encoding/decoding errors
    CborEncodingError,
    CborDecodingError,
    CborTypeMismatch,
    CborValueOutOfRange,
    CborUnexpectedEndOfData,
    CborInvalidIndefiniteLength,
    CborInvalidBreakCode,

    // I/O errors
    IoError,

    // Base64 encoding/decoding errors
    Base64EncodingError,
    Base64DecodingError,
    Base64InvalidPadding,
    Base64InvalidCharacter,

    // JSON errors
    JsonError,
    JsonParsingError,
    JsonInvalidValue,
    JsonMissingField,

    // Key-related errors
    KeyNotFound,
    KeyInvalidFormat,
    KeyInvalidSize,
    KeyInvalidType,
    KeyInvalidAlgorithm,

    // Validation errors
    InvalidIssuer,
    TokenExpired,
    TokenNotActive,
    InvalidAudience,
    InvalidSubject,
    InvalidClaimType,
    InvalidClaimValue,
    RequiredClaimMissing,
    TagMismatch,
    ExpectedCwtTag,
    ExpectedCoseMac0Tag,
    FailedToMac,
    InvalidSignature,
    UriNotAllowed,
    IpNotAllowed,
    AsnNotAllowed,
    RenewalClaimError,

    // Token format errors
    InvalidTokenFormat,
    InvalidTokenStructure,
    InvalidTokenHeader,
    InvalidTokenPayload,
    InvalidTokenSignature,

    // Algorithm errors
    UnsupportedAlgorithm,
    InvalidAlgorithmForKeyType,

    // Other errors
    OutOfMemory,
    InvalidArgument,
    MemoryAllocationError,
    InternalError,
    Unexpected,
};

/// Error context for providing more detailed error information
pub const ErrorContext = struct {
    /// The error that occurred
    error_type: Error,
    /// Additional context about the error
    message: []const u8,
    /// The source of the error (e.g., function name)
    source: []const u8,

    /// Create a new error context
    pub fn init(error_type: Error, message: []const u8, source: []const u8) ErrorContext {
        return .{
            .error_type = error_type,
            .message = message,
            .source = source,
        };
    }
};

/// Converts an error to a human-readable string.
pub fn errorToString(err: Error) []const u8 {
    return switch (err) {
        // CBOR encoding/decoding errors
        Error.CborEncodingError => "CBOR encoding error",
        Error.CborDecodingError => "CBOR decoding error",
        Error.CborTypeMismatch => "CBOR type mismatch",
        Error.CborValueOutOfRange => "CBOR value out of range",
        Error.CborUnexpectedEndOfData => "CBOR unexpected end of data",
        Error.CborInvalidIndefiniteLength => "CBOR invalid indefinite length",
        Error.CborInvalidBreakCode => "CBOR invalid break code",

        // I/O errors
        Error.IoError => "I/O error",

        // Base64 encoding/decoding errors
        Error.Base64EncodingError => "Base64 encoding error",
        Error.Base64DecodingError => "Base64 decoding error",
        Error.Base64InvalidPadding => "Base64 invalid padding",
        Error.Base64InvalidCharacter => "Base64 invalid character",

        // JSON errors
        Error.JsonError => "JSON error",
        Error.JsonParsingError => "JSON parsing error",
        Error.JsonInvalidValue => "JSON invalid value",
        Error.JsonMissingField => "JSON missing field",

        // Key-related errors
        Error.KeyNotFound => "Key not found",
        Error.KeyInvalidFormat => "Key invalid format",
        Error.KeyInvalidSize => "Key invalid size",
        Error.KeyInvalidType => "Key invalid type",
        Error.KeyInvalidAlgorithm => "Key invalid algorithm",

        // Validation errors
        Error.InvalidIssuer => "Invalid issuer",
        Error.TokenExpired => "Token expired",
        Error.TokenNotActive => "Token not yet active",
        Error.InvalidAudience => "Invalid audience",
        Error.InvalidSubject => "Invalid subject",
        Error.InvalidClaimType => "Invalid claim type",
        Error.InvalidClaimValue => "Invalid claim value",
        Error.RequiredClaimMissing => "Required claim missing",
        Error.TagMismatch => "Tag mismatch",
        Error.ExpectedCwtTag => "Expected CWT tag",
        Error.ExpectedCoseMac0Tag => "Expected COSE_Mac0 tag",
        Error.FailedToMac => "Failed to MAC token",
        Error.InvalidSignature => "Invalid signature",
        Error.UriNotAllowed => "URI not allowed",
        Error.IpNotAllowed => "IP not allowed",
        Error.AsnNotAllowed => "ASN not allowed",
        Error.RenewalClaimError => "Renewal claim error",

        // Token format errors
        Error.InvalidTokenFormat => "Invalid token format",
        Error.InvalidTokenStructure => "Invalid token structure",
        Error.InvalidTokenHeader => "Invalid token header",
        Error.InvalidTokenPayload => "Invalid token payload",
        Error.InvalidTokenSignature => "Invalid token signature",

        // Algorithm errors
        Error.UnsupportedAlgorithm => "Unsupported algorithm",
        Error.InvalidAlgorithmForKeyType => "Invalid algorithm for key type",

        // Other errors
        Error.OutOfMemory => "Out of memory",
        Error.InvalidArgument => "Invalid argument",
        Error.MemoryAllocationError => "Memory allocation error",
        Error.InternalError => "Internal error",
        Error.Unexpected => "Unexpected error",
    };
}

/// Format an error context as a string
pub fn formatErrorContext(context: ErrorContext, allocator: std.mem.Allocator) ![]const u8 {
    return std.fmt.allocPrint(allocator, "Error: {s}\nMessage: {s}\nSource: {s}", .{ errorToString(context.error_type), context.message, context.source });
}

test "error to string" {
    try std.testing.expectEqualStrings("Token expired", errorToString(Error.TokenExpired));
    try std.testing.expectEqualStrings("Invalid issuer", errorToString(Error.InvalidIssuer));
}
