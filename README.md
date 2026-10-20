# Common Access Token (CAT) for Zig

Create and validate Common Access Tokens (CAT) in Zig with HMAC signatures.

## What is CAT?

CAT is a token format for authorization and authentication in distributed systems, especially media and content delivery applications. It gives you a secure, compact, and efficient way to pass claims and authorization information between parties.

It's built on established standards:

- It's based on the [CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392) format.
- It uses [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152) for cryptographic operations.
- It's a binary alternative to JWT, with smaller tokens and more efficient processing.

## Overview

This library fully implements CAT generation and validation with HMAC signatures. It's designed to work with other implementations, including:

- [node-cat](https://github.com/Eyevinn/node-cat)
- [common-access-token](https://github.com/fastly/rust-cat)

Why use CAT tokens?

- They're compact: the binary format makes tokens smaller than text-based formats.
- They're efficient: CBOR encoding and decoding are faster and need less processing power.
- They're secure: they use established cryptographic standards.
- You can extend them with custom claims and extensions.

## Features

- Tokens:
  - Generate CAT tokens with HMAC signatures (HS256).
  - Validate CAT tokens with thorough security checks.
  - Check token expiration and other time-based rules.

- Claims:
  - Standard CWT claims, including:
    - Issuer
    - Subject
    - Audience
    - Expiration
  - CAT-specific claims:
    - Version
    - Renewal
    - Usage
    - Data
    - Authorization
  - Media over QUIC (MoQT) scopes and revalidation, from draft-ietf-moq-c4m.
  - Extend tokens with custom claims.

- CBOR:
  - Fast CBOR encoding and decoding.
  - All CBOR data types.
  - Indefinite-length arrays, maps, and strings.
  - Floating-point numbers.
  - Tagged values.

- Errors:
  - A full set of error types.
  - Detailed error messages.
  - Context about errors.
  - Ways to recover from errors.

- Integration:
  - Works with other CAT implementations.
  - Easy to add to your Zig applications.
  - Full documentation and examples.

## Installation

Add the library to your `build.zig.zon` file:

```zig
.dependencies = .{
    .zig_cat = .{
        .url = "https://github.com/jedisct1/zig-common-access-token/archive/refs/heads/main.tar.gz",
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

### Create a token

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

This creates a CAT token with standard claims.

### Validate a token

```zig
const std = @import("std");
const cat = @import("cat");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // The token to validate (e.g., from a client request)
    const token = "2D3RhEOhAQWhBExTeW1tZXRyaWMyNTZYS6YHWCA1YmJjNDI2NWVmYTAxOGI4YjU4Y2I5OTQyY2IwODFmMQFnZXhhbXBsZQQaaQpK1gYaaQpKXgJndXNlcjEyMwNnc2VydmljZVggNRE3wudeG0Fd-vJMZiLpNRO6WU9lrtByioSvzuAEi7U";

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
    if (claims.getIssuer()) |issuer| {
        std.debug.print("Issuer: {s}\n", .{issuer});
    }
    if (claims.getSubject()) |subject| {
        std.debug.print("Subject: {s}\n", .{subject});
    }
}
```

### Authorize Media over QUIC requests

The library supports the `moqt` and `moqt-reval` claims from [draft-ietf-moq-c4m](https://datatracker.ietf.org/doc/draft-ietf-moq-c4m/). With them, a token says which Media over QUIC Transport (MoQT) actions a client can take, and on which tracks.

A `moqt` claim is a list of scopes. Each scope lists actions, plus optional matches on the track namespace and the track name. Matches can be exact, prefix, or suffix. They compare raw bytes, with no normalization.

```zig
// Alice can connect, and publish video tracks under example.com/alice.
try claims.setMoqt(&.{.{
    .actions = &.{ .ClientSetup, .PublishNamespace, .Publish },
    .namespace = &.{ .{ .Exact = "example.com" }, .{ .Exact = "alice" } },
    .track = .{ .Prefix = "video-" },
}});

// Relays recheck the token at least every 5 minutes while she publishes.
try claims.setMoqtReval(300);
```

On the relay, give `validate` the request you want to check:

```zig
var claims = try cat_instance.validate(token, .Mac, .{
    .issuer = "issuer.example.com",
    .moqt_request = .{ .action = .Publish, .namespace = &.{ "example.com", "alice" }, .track = "video-hd" },
    .moqt_min_reval_interval = 60,
});
defer claims.deinit();
```

A few things to know:

- With a `moqt_request`, a token without a `moqt` claim can't do anything. The draft blocks every action that no scope allows.
- Setup actions only need to be listed. Namespace actions also check the namespace. Track actions check the track name too.
- Set `moqt_min_reval_interval` to the shortest interval your relay can handle, in seconds. If you leave it out, tokens with a `moqt-reval` claim are rejected.
- To revalidate a token, just call `validate` again.
- To check many requests against one token, validate it once. Then parse the claim with `claims.getMoqt(allocator)`, and call `permits` for each request.
- The draft doesn't assign claim keys yet. The library uses 327 and 328, like the draft's test vectors and rust-cat. They might change.
- Composite claims (`or`, `and`) aren't supported yet, since their keys aren't assigned either. A `moqt` claim nested inside one doesn't count, so the token is denied.

## Examples

You'll find ready-to-use examples in the `examples/` directory:

- generate.zig: Create a basic token with standard claims.
- validate.zig: Validate tokens and read their claims.
- interop.zig: Test interoperability with the NodeJS implementation (node-cat).
- cat_claims.zig: Use CAT-specific claims for more advanced use cases.
- moqt.zig: Issue a Media over QUIC token, and check a few relay requests against it.
- minimal.zig: Try the basic base64 encoding utilities.

Run them with:

```bash
# Generate a token
zig build generate

# Validate a token (replace <token> with an actual token)
zig build validate -- <token>

# Test interoperability with NodeJS implementation
zig build interop [-- <token>]

# Use CAT-specific claims
zig build cat_claims

# Authorize Media over QUIC requests
zig build moqt

# Run minimal example
zig build minimal
```

## Security

Keep these security practices in mind when you use CAT tokens in your applications:

1. Keys:
   - Store your signing keys securely.
   - Rotate your keys periodically.
   - Use different keys for different environments.

2. Validation:
   - Always validate tokens before you trust their contents.
   - Check expiration times.
   - Verify the issuer and audience claims.

3. Token lifetime:
   - Use short-lived tokens when you can.
   - For longer sessions, consider a refresh token pattern.

4. Claims:
   - Only put information you need in tokens.
   - Be careful with sensitive data in claims.

## Compatibility

The library is designed to work with other CAT implementations:

- [node-cat](https://github.com/Eyevinn/node-cat): The NodeJS reference implementation
- [common-access-token](https://github.com/fastly/rust-cat): The Rust implementation
- Other implementations that follow the CAT specification

## License

This project uses the MIT License. See the LICENSE file for details.
