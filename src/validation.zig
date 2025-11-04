const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;

const Error = @import("error.zig").Error;
const Claims = @import("claims.zig").Claims;
const ClaimValue = @import("claims.zig").ClaimValue;
const LABEL_CATU = @import("claims.zig").LABEL_CATU;
const LABEL_CATM = @import("claims.zig").LABEL_CATM;
const LABEL_CATREPLAY = @import("claims.zig").LABEL_CATREPLAY;

/// URI components for CATU validation
pub const UriComponent = enum(u64) {
    Scheme = 0,
    Host = 1,
    Port = 2,
    Path = 3,
    Query = 4,
    ParentPath = 5,
    Filename = 6,
    Stem = 7,
    Extension = 8,
};

/// Match types for CATU validation
pub const MatchType = enum(i64) {
    Exact = 0,
    Prefix = 1,
    Suffix = 2,
    Contains = 3,
    Regex = 4,
    Sha256 = -1,
    Sha512_256 = -2,
};

/// CATREPLAY values
pub const ReplayMode = enum(i64) {
    Permitted = 0,
    Prohibited = 1,
    ReuseDetection = 2,
};

/// Parsed URI structure
const ParsedUri = struct {
    scheme: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    path: ?[]const u8 = null,
    query: ?[]const u8 = null,
    parent_path: ?[]const u8 = null,
    filename: ?[]const u8 = null,
    stem: ?[]const u8 = null,
    extension: ?[]const u8 = null,
};

/// Parse a URI into components
fn parseUri(allocator: Allocator, uri: []const u8) !ParsedUri {
    var result = ParsedUri{};

    // Simple URI parsing - find scheme
    if (std.mem.indexOf(u8, uri, "://")) |scheme_end| {
        result.scheme = try allocator.dupe(u8, uri[0..scheme_end]);

        var rest = uri[scheme_end + 3..];

        // Find path start
        if (std.mem.indexOfAny(u8, rest, "/?#")) |path_start| {
            const authority = rest[0..path_start];
            rest = rest[path_start..];

            // Parse authority (host:port)
            if (std.mem.indexOf(u8, authority, ":")) |port_start| {
                result.host = try allocator.dupe(u8, authority[0..port_start]);
                const port_str = authority[port_start + 1..];
                result.port = try std.fmt.parseInt(u16, port_str, 10);
            } else {
                result.host = try allocator.dupe(u8, authority);
            }

            // Parse path and query
            if (std.mem.indexOf(u8, rest, "?")) |query_start| {
                result.path = try allocator.dupe(u8, rest[0..query_start]);

                // Check for fragment
                const query_rest = rest[query_start + 1..];
                if (std.mem.indexOf(u8, query_rest, "#")) |fragment_start| {
                    result.query = try allocator.dupe(u8, query_rest[0..fragment_start]);
                } else {
                    result.query = try allocator.dupe(u8, query_rest);
                }
            } else if (std.mem.indexOf(u8, rest, "#")) |fragment_start| {
                result.path = try allocator.dupe(u8, rest[0..fragment_start]);
            } else {
                result.path = try allocator.dupe(u8, rest);
            }
        } else {
            // No path, just authority
            result.host = try allocator.dupe(u8, rest);
        }
    }

    // Parse path components if we have a path
    if (result.path) |path| {
        // Find last slash for parent path
        if (std.mem.lastIndexOf(u8, path, "/")) |last_slash| {
            if (last_slash < path.len - 1) {
                result.parent_path = try allocator.dupe(u8, path[0..last_slash + 1]);
                result.filename = try allocator.dupe(u8, path[last_slash + 1..]);

                // Parse filename into stem and extension
                if (result.filename) |filename| {
                    if (std.mem.lastIndexOf(u8, filename, ".")) |dot_pos| {
                        if (dot_pos > 0 and dot_pos < filename.len - 1) {
                            result.stem = try allocator.dupe(u8, filename[0..dot_pos]);
                            result.extension = try allocator.dupe(u8, filename[dot_pos + 1..]);
                        }
                    } else {
                        result.stem = try allocator.dupe(u8, filename);
                    }
                }
            } else {
                result.parent_path = try allocator.dupe(u8, path);
            }
        }
    }

    return result;
}

/// Free a ParsedUri
fn freeParsedUri(allocator: Allocator, uri: ParsedUri) void {
    if (uri.scheme) |s| allocator.free(s);
    if (uri.host) |h| allocator.free(h);
    if (uri.path) |p| allocator.free(p);
    if (uri.query) |q| allocator.free(q);
    if (uri.parent_path) |pp| allocator.free(pp);
    if (uri.filename) |f| allocator.free(f);
    if (uri.stem) |s| allocator.free(s);
    if (uri.extension) |e| allocator.free(e);
}

/// Check if a component matches a match specification
fn matchesComponent(component_value: ?[]const u8, match_type: MatchType, match_value: []const u8) bool {
    const value = component_value orelse return false;

    return switch (match_type) {
        .Exact => std.mem.eql(u8, value, match_value),
        .Prefix => std.mem.startsWith(u8, value, match_value),
        .Suffix => std.mem.endsWith(u8, value, match_value),
        .Contains => std.mem.indexOf(u8, value, match_value) != null,
        .Regex => {
            // Simple regex support - not implementing full regex for now
            // This would require a regex library
            return false;
        },
        .Sha256 => {
            // Hash comparison - not implementing for now
            // Would need to hash the component and compare
            return false;
        },
        .Sha512_256 => {
            // Hash comparison - not implementing for now
            return false;
        },
    };
}

/// Validate CATU (URI) claim
pub fn validateCatu(allocator: Allocator, claims: Claims, uri: []const u8) !void {
    const catu_claim = claims.getClaim(LABEL_CATU) orelse return; // No CATU claim, nothing to validate

    const component_map = switch (catu_claim) {
        .Map => |map| map,
        else => return Error.InvalidClaimValue,
    };

    // Parse the URI
    const parsed = try parseUri(allocator, uri);
    defer freeParsedUri(allocator, parsed);

    // Validate each component in the CATU claim
    var it = component_map.iterator();
    while (it.next()) |entry| {
        const component_key = entry.key_ptr.*;
        const component_value = entry.value_ptr.*;

        // Get the match specifications for this component
        const match_map = switch (component_value) {
            .Map => |map| map,
            else => return Error.InvalidClaimValue,
        };

        // Get the actual URI component value
        const uri_component_value: ?[]const u8 = switch (component_key) {
            0 => parsed.scheme, // Scheme
            1 => parsed.host,   // Host
            2 => null, // Port - would need string conversion
            3 => parsed.path,   // Path
            4 => parsed.query,  // Query
            5 => parsed.parent_path, // ParentPath
            6 => parsed.filename,    // Filename
            7 => parsed.stem,        // Stem
            8 => parsed.extension,   // Extension
            else => null,
        };

        // Check if any match specification passes
        var match_it = match_map.iterator();
        var any_match = false;

        while (match_it.next()) |match_entry| {
            const match_type_int = match_entry.key_ptr.*;
            const match_value_claim = match_entry.value_ptr.*;

            // Convert match type integer to enum
            const match_type: MatchType = switch (match_type_int) {
                0 => .Exact,
                1 => .Prefix,
                2 => .Suffix,
                3 => .Contains,
                4 => .Regex,
                else => if (match_type_int == @intFromEnum(MatchType.Sha256)) .Sha256 else if (match_type_int == @intFromEnum(MatchType.Sha512_256)) .Sha512_256 else continue,
            };

            // Get the match value as string
            const match_value_str = switch (match_value_claim) {
                .String => |s| s,
                else => continue,
            };

            if (matchesComponent(uri_component_value, match_type, match_value_str)) {
                any_match = true;
                break;
            }
        }

        if (!any_match) {
            return Error.InvalidUriClaim;
        }
    }
}

/// Validate CATM (HTTP method) claim
pub fn validateCatm(claims: Claims, http_method: []const u8) !void {
    const catm_claim = claims.getClaim(LABEL_CATM) orelse return; // No CATM claim, nothing to validate

    const methods_array = switch (catm_claim) {
        .Array => |array| array,
        else => return Error.InvalidClaimValue,
    };

    // Check if the provided method is in the allowed list (case-insensitive)
    for (methods_array.items) |method_value| {
        const method_str = switch (method_value) {
            .String => |s| s,
            else => continue,
        };

        if (std.ascii.eqlIgnoreCase(http_method, method_str)) {
            return; // Method is allowed
        }
    }

    // Method not found in allowed list
    return Error.InvalidMethodClaim;
}

/// Validate CATREPLAY claim
pub fn validateCatreplay(claims: Claims, token_seen_before: bool) !void {
    const catreplay_claim = claims.getClaim(LABEL_CATREPLAY) orelse return; // No CATREPLAY claim, nothing to validate

    const replay_mode_int = switch (catreplay_claim) {
        .Integer => |i| i,
        else => return Error.InvalidClaimValue,
    };

    const replay_mode: ReplayMode = switch (replay_mode_int) {
        0 => .Permitted,
        1 => .Prohibited,
        2 => .ReuseDetection,
        else => return Error.InvalidClaimValue,
    };

    switch (replay_mode) {
        .Permitted => {
            // Token reuse is allowed, no validation needed
        },
        .Prohibited => {
            if (token_seen_before) {
                return Error.TokenReplayProhibited;
            }
        },
        .ReuseDetection => {
            // Reuse detection is enabled - caller should track token usage
            // but we don't fail validation
        },
    }
}
