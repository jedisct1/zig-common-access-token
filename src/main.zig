// Common Access Token (CAT) implementation in Zig
//
// This library provides functionality for generating and validating
// Common Access Tokens (CAT) using HMAC signatures.
//
// Based on the CTA-5007 specification and compatible with other
// implementations like node-cat and common-access-token (Rust).

pub const cat = @import("cat.zig");
pub const claims = @import("claims.zig");
pub const cose = @import("cose.zig");
pub const errors = @import("error.zig");
pub const util = @import("util.zig");

// Import zbor for CBOR serialization/deserialization
pub const zbor = @import("zbor.zig");

// Re-export main types and functions for easier use
pub const Cat = cat.Cat;
pub const CatOptions = cat.CatOptions;
pub const CatGenerateOptions = cat.CatGenerateOptions;
pub const CatValidationOptions = cat.CatValidationOptions;
pub const CatValidationType = cat.CatValidationType;
pub const Claims = claims.Claims;
pub const ClaimValue = claims.ClaimValue;
pub const Error = errors.Error;

test {
    // Run all tests
    _ = @import("cat.zig");
    _ = @import("claims.zig");
    _ = @import("cose.zig");
    _ = @import("error.zig");
    _ = @import("util.zig");
}
