# Common Access Token (CAT) for Zig

A Zig implementation of the Common Access Token (CAT) specification with HMAC signatures.

## What is CAT?

Common Access Token (CAT) is a token format designed for authorization and authentication in distributed systems, particularly for media and content delivery applications. It provides a secure, compact, and efficient way to represent claims and authorization information between parties.

CAT is built on established standards:
- Based on [CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392) format
- Uses [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152) for cryptographic operations
- Provides a binary alternative to JWT with smaller token sizes and more efficient processing

## Overview

This library provides a complete implementation for generating and validating Common Access Tokens (CAT) using HMAC signatures. It is designed to be interoperable with other implementations like [node-cat](https://github.com/Eyevinn/node-cat) and [common-access-token](https://github.com/jedisct1/rust-common-access-token).

Key benefits of using CAT tokens:
- **Compact**: Binary format results in smaller token sizes compared to text-based formats
- **Efficient**: CBOR encoding/decoding is faster and requires less processing power
- **Secure**: Built on established cryptographic standards
- **Extensible**: Supports custom claims and extensions

## Features

- **Token Operations**:
  - Generate CAT tokens with HMAC signatures (HS256)
  - Validate CAT tokens with comprehensive security checks
  - Support for token expiration and time-based validation

- **Claims Support**:
  - Standard CWT claims (issuer, subject, audience, expiration, etc.)
  - CAT-specific claims (version, renewal, usage, data, authorization)
  - Custom claim extension capability

- **CBOR Implementation**:
  - High-performance CBOR encoding/decoding
  - Support for all CBOR data types
  - Support for indefinite-length arrays, maps, and strings
  - Support for floating-point numbers
  - Support for tagged values

- **Error Handling**:
  - Comprehensive error types
  - Detailed error messages
  - Error context information
  - Error recovery mechanisms

- **Integration**:
  - Interoperability with other CAT implementations
  - Easy integration with Zig applications
  - Comprehensive documentation and examples

## Installation

Add this library to your `build.zig.zon` file:

```zig
.dependencies = .{
    .zig_cat = .{
        .url = "https://github.com/yourusername/zig-cat/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const zig_cat = b.dependency("zig_cat", .{
    .target = target,
    .optimize = optimize,
});
exe.addModule("cat", zig_cat.module("cat"));
```

## Usage

### Token Generation

This example demonstrates how to create a CAT token with standard claims:

```zig
const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a key for token signing
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try cat.util.hexToBytes(allocator, key_hex);
    defer allocator.free(key);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(allocator);
    defer keys.deinit();
    try keys.put("Symmetric256", key);

    // Create CAT options
    const cat_options = cat.CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
    };

    // Create a CAT instance
    var cat_instance = cat.Cat.init(allocator, cat_options);
    defer cat_instance.deinit();

    // Create claims
    var claims = cat.Claims.init(allocator);
    defer claims.deinit();

    try claims.setIssuer("example");
    try claims.setSubject("user123");
    try claims.setAudience("service");

    const now = cat.util.currentTimeSecs();
    try claims.setExpiration(now + 120); // 2 minutes from now
    try claims.setIssuedAt(now);

    // Generate token
    const token = try cat_instance.generate(claims, .{
        .validation_type = cat.CatValidationType.Mac,
        .alg = "HS256",
        .kid = "Symmetric256",
        .generate_cwt_id = true,
    });
    defer allocator.free(token);

    std.debug.print("Generated token: {s}\n", .{token});
}
```

### Token Validation

```zig
const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a key for token validation
    const key_hex = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388";
    const key = try cat.util.hexToBytes(allocator, key_hex);
    defer allocator.free(key);

    // Create a map of keys
    var keys = std.StringHashMap([]const u8).init(allocator);
    defer keys.deinit();
    try keys.put("Symmetric256", key);

    // Create CAT options
    const cat_options = cat.CatOptions{
        .keys = keys,
        .expect_cwt_tag = true,
    };

    // Create a CAT instance
    var cat_instance = cat.Cat.init(allocator, cat_options);
    defer cat_instance.deinit();

    // Validate the token
    var claims = try cat_instance.validate(token, cat.CatValidationType.Mac, .{
        .issuer = "example",
        .audience = null,
    });
    defer claims.deinit();

    std.debug.print("Token is valid!\n", .{});
}
```

## Examples

The library includes several ready-to-use examples in the `examples/` directory:

- **generate.zig**: Demonstrates basic token generation with standard claims
- **validate.zig**: Shows how to validate tokens and extract claims
- **interop.zig**: Tests interoperability with the NodeJS implementation
- **cat_claims.zig**: Demonstrates using CAT-specific claims for advanced use cases

To run an example:

```bash
# Generate a token
zig build generate

# Validate a token (replace <token> with an actual token)
zig build validate -- <token>

# Test interoperability with NodeJS implementation
zig build interop [-- <token>]

# Use CAT-specific claims
zig build cat_claims
```

## Security Considerations

When using CAT tokens in your applications, keep these security best practices in mind:

1. **Key Management**:
   - Store signing keys securely
   - Rotate keys periodically
   - Use different keys for different environments

2. **Token Validation**:
   - Always validate tokens before trusting their contents
   - Check expiration times
   - Verify the issuer and audience claims

3. **Token Lifetime**:
   - Use short-lived tokens when possible
   - For longer sessions, consider refresh token patterns

4. **Claims**:
   - Only include necessary information in tokens
   - Be cautious with sensitive data in claims

## Compatibility

This library is designed to be interoperable with other CAT implementations:

- **[node-cat](https://github.com/Eyevinn/node-cat)**: The NodeJS reference implementation
- **[common-access-token](https://github.com/jedisct1/rust-common-access-token)**: The Rust implementation
- Other implementations that follow the CAT specification

## License

This project is licensed under the MIT License - see the LICENSE file for details.
