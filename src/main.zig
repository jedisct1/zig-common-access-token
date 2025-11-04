///! Common Access Token (CAT) implementation
///!
///! HMAC-based token generation and validation per CTA-5007.
///! Compatible with node-cat and rust-cat implementations.
pub const cat = @import("cat.zig");
pub const claims = @import("claims.zig");
pub const cose = @import("cose.zig");
pub const errors = @import("error.zig");
pub const util = @import("util.zig");
pub const zbor = @import("zbor.zig");

pub const Cat = cat.Cat;
pub const CatOptions = cat.CatOptions;
pub const CatGenerateOptions = cat.CatGenerateOptions;
pub const CatValidationOptions = cat.CatValidationOptions;
pub const CatValidationType = cat.CatValidationType;
pub const Claims = claims.Claims;
pub const ClaimValue = claims.ClaimValue;
pub const Error = errors.Error;

test {
    _ = @import("cat.zig");
    _ = @import("claims.zig");
    _ = @import("cose.zig");
    _ = @import("error.zig");
    _ = @import("util.zig");
}
