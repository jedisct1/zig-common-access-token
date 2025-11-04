///! CBOR (Concise Binary Object Representation) implementation
///!
///! This module provides functionality for encoding and decoding CBOR data
///! as defined in RFC 7049 and RFC 8949.
///!
///! Performance optimizations:
///! - Uses preallocated buffers where possible
///! - Minimizes memory allocations
///! - Provides streaming encoding/decoding for large payloads
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// CBOR major types as defined in RFC 8949
pub const MajorType = enum(u3) {
    UnsignedInt = 0, // Major type 0: unsigned integer
    NegativeInt = 1, // Major type 1: negative integer
    ByteString = 2, // Major type 2: byte string
    TextString = 3, // Major type 3: text string
    Array = 4, // Major type 4: array
    Map = 5, // Major type 5: map
    Tag = 6, // Major type 6: tag
    Simple = 7, // Major type 7: simple/float

    /// Convert a byte to a major type
    pub fn fromByte(byte: u8) MajorType {
        return @enumFromInt((byte >> 5) & 0x7);
    }

    /// Convert a major type to a byte (with additional info 0)
    pub fn toByte(self: MajorType) u8 {
        return @as(u8, @intFromEnum(self)) << 5;
    }
};

/// CBOR additional info values
pub const AdditionalInfo = struct {
    pub const DIRECT: u8 = 23; // Values 0-23 are encoded directly in the additional info
    pub const ONE_BYTE: u8 = 24; // Value is in the next 1 byte
    pub const TWO_BYTES: u8 = 25; // Value is in the next 2 bytes
    pub const FOUR_BYTES: u8 = 26; // Value is in the next 4 bytes
    pub const EIGHT_BYTES: u8 = 27; // Value is in the next 8 bytes
    pub const INDEFINITE: u8 = 31; // Indefinite length
};

/// CBOR simple values
pub const SimpleValue = struct {
    pub const FALSE: u8 = 20; // false
    pub const TRUE: u8 = 21; // true
    pub const NULL: u8 = 22; // null
    pub const UNDEFINED: u8 = 23; // undefined
};

/// CBOR encoder with performance optimizations
pub const Encoder = struct {
    allocator: Allocator,
    buffer: std.ArrayList(u8),
    indefinite_level: usize = 0, // Track nesting level of indefinite-length items

    /// Initialize a new encoder with default capacity
    pub fn init(allocator: Allocator) Encoder {
        return initCapacity(allocator, 256); // Default to 256 bytes
    }

    /// Initialize a new encoder with specified capacity
    pub fn initCapacity(allocator: Allocator, capacity: usize) Encoder {
        return .{
            .allocator = allocator,
            .buffer = std.ArrayList(u8).initCapacity(allocator, capacity) catch
                std.ArrayList(u8){},
        };
    }

    /// Free resources
    pub fn deinit(self: *Encoder) void {
        self.buffer.deinit(self.allocator);
    }

    /// Reset the encoder to be reused
    pub fn reset(self: *Encoder) void {
        self.buffer.clearRetainingCapacity();
        self.indefinite_level = 0;
    }

    /// Get the current size of the encoded data
    pub fn len(self: *const Encoder) usize {
        return self.buffer.items.len;
    }

    /// Begin a fixed-length CBOR array
    pub fn beginArray(self: *Encoder, length: usize) !void {
        try self.writeTypeAndValue(MajorType.Array, length);
    }

    /// Begin an indefinite-length CBOR array
    pub fn beginArrayIndefinite(self: *Encoder) !void {
        try self.buffer.append(self.allocator,MajorType.Array.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    /// End a CBOR array
    pub fn endArray(self: *Encoder) !void {
        // Only needed for indefinite-length arrays
        if (self.indefinite_level > 0) {
            try self.buffer.append(self.allocator,0xFF); // Break code
            self.indefinite_level -= 1;
        }
    }

    /// Begin a fixed-length CBOR map
    pub fn beginMap(self: *Encoder, length: usize) !void {
        try self.writeTypeAndValue(MajorType.Map, length);
    }

    /// Begin an indefinite-length CBOR map
    pub fn beginMapIndefinite(self: *Encoder) !void {
        try self.buffer.append(self.allocator,MajorType.Map.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    /// End a CBOR map
    pub fn endMap(self: *Encoder) !void {
        // Only needed for indefinite-length maps
        if (self.indefinite_level > 0) {
            try self.buffer.append(self.allocator,0xFF); // Break code
            self.indefinite_level -= 1;
        }
    }

    /// Helper function to write a type and value
    fn writeTypeAndValue(self: *Encoder, major_type: MajorType, value: anytype) !void {
        const T = @TypeOf(value);
        const unsigned_value = if (T == usize or T == u8 or T == u16 or T == u32 or T == u64 or T == u128)
            value
        else if (T == isize or T == i8 or T == i16 or T == i32 or T == i64 or T == i128)
            if (value >= 0) @as(u64, @intCast(value)) else @as(u64, @intCast(-(value + 1)))
        else
            @compileError("Unsupported type for writeTypeAndValue");

        const type_byte = major_type.toByte();

        if (unsigned_value <= AdditionalInfo.DIRECT) {
            try self.buffer.append(self.allocator,type_byte | @as(u8, @intCast(unsigned_value)));
        } else if (unsigned_value <= std.math.maxInt(u8)) {
            try self.buffer.append(self.allocator,type_byte | AdditionalInfo.ONE_BYTE);
            try self.buffer.append(self.allocator,@as(u8, @intCast(unsigned_value)));
        } else if (unsigned_value <= std.math.maxInt(u16)) {
            try self.buffer.append(self.allocator,type_byte | AdditionalInfo.TWO_BYTES);
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 8) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast(unsigned_value & 0xFF)));
        } else if (unsigned_value <= std.math.maxInt(u32)) {
            try self.buffer.append(self.allocator,type_byte | AdditionalInfo.FOUR_BYTES);
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 24) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 16) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 8) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast(unsigned_value & 0xFF)));
        } else {
            try self.buffer.append(self.allocator,type_byte | AdditionalInfo.EIGHT_BYTES);
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 56) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 48) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 40) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 32) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 24) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 16) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((unsigned_value >> 8) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast(unsigned_value & 0xFF)));
        }
    }

    /// Push an integer
    pub fn pushInt(self: *Encoder, value: anytype) !void {
        const T = @TypeOf(value);

        if (value >= 0) {
            // Unsigned integer or positive signed integer
            try self.writeTypeAndValue(MajorType.UnsignedInt, value);
        } else {
            // Negative integer
            // For negative integers, CBOR uses -1 - n (where n is the negative value)
            // So we need to convert to the absolute value of value + 1
            const abs_value = if (T == i8 or T == i16 or T == i32 or T == i64 or T == i128 or T == isize)
                if (value == std.math.minInt(T))
                    @as(u64, @intCast(-(value + 1)))
                else
                    @as(u64, @intCast(-(value + 1)))
            else
                @compileError("Unsupported type for pushInt");

            try self.writeTypeAndValue(MajorType.NegativeInt, abs_value);
        }
    }

    /// Push a boolean value
    pub fn pushBool(self: *Encoder, value: bool) !void {
        try self.buffer.append(self.allocator,MajorType.Simple.toByte() | (if (value) SimpleValue.TRUE else SimpleValue.FALSE));
    }

    /// Push a null value
    pub fn pushNull(self: *Encoder) !void {
        try self.buffer.append(self.allocator,MajorType.Simple.toByte() | SimpleValue.NULL);
    }

    /// Push an undefined value
    pub fn pushUndefined(self: *Encoder) !void {
        try self.buffer.append(self.allocator,MajorType.Simple.toByte() | SimpleValue.UNDEFINED);
    }

    /// Push a floating-point value
    pub fn pushFloat(self: *Encoder, value: anytype) !void {
        const T = @TypeOf(value);

        if (T == f16) {
            try self.buffer.append(self.allocator,MajorType.Simple.toByte() | AdditionalInfo.TWO_BYTES);
            const bits = @as(u16, @bitCast(value));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 8) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast(bits & 0xFF)));
        } else if (T == f32) {
            try self.buffer.append(self.allocator,MajorType.Simple.toByte() | AdditionalInfo.FOUR_BYTES);
            const bits = @as(u32, @bitCast(value));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 24) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 16) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 8) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast(bits & 0xFF)));
        } else if (T == f64) {
            try self.buffer.append(self.allocator,MajorType.Simple.toByte() | AdditionalInfo.EIGHT_BYTES);
            const bits = @as(u64, @bitCast(value));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 56) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 48) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 40) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 32) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 24) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 16) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast((bits >> 8) & 0xFF)));
            try self.buffer.append(self.allocator,@as(u8, @intCast(bits & 0xFF)));
        } else {
            @compileError("Unsupported type for pushFloat");
        }
    }

    /// Push a byte string
    pub fn pushBytes(self: *Encoder, bytes: []const u8) !void {
        try self.writeTypeAndValue(MajorType.ByteString, bytes.len);
        try self.buffer.appendSlice(self.allocator,bytes);
    }

    /// Push an indefinite-length byte string
    pub fn pushBytesIndefinite(self: *Encoder) !void {
        try self.buffer.append(self.allocator,MajorType.ByteString.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    /// Push a text string
    pub fn pushText(self: *Encoder, text: []const u8) !void {
        try self.writeTypeAndValue(MajorType.TextString, text.len);
        try self.buffer.appendSlice(self.allocator,text);
    }

    /// Push an indefinite-length text string
    pub fn pushTextIndefinite(self: *Encoder) !void {
        try self.buffer.append(self.allocator,MajorType.TextString.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    /// Push a tag
    pub fn pushTag(self: *Encoder, tag: u64) !void {
        try self.writeTypeAndValue(MajorType.Tag, tag);
    }

    /// Push a break code (to end indefinite-length items)
    pub fn pushBreak(self: *Encoder) !void {
        try self.buffer.append(self.allocator,0xFF);
        if (self.indefinite_level > 0) {
            self.indefinite_level -= 1;
        }
    }

    /// Push raw CBOR data
    pub fn pushRaw(self: *Encoder, data: []const u8) !void {
        try self.buffer.appendSlice(self.allocator,data);
    }

    /// Finish encoding and return the result
    pub fn finish(self: *Encoder) ![]u8 {
        const result = try self.allocator.dupe(u8, self.buffer.items);
        return result;
    }
};

/// CBOR decoder with performance optimizations and support for more CBOR features
pub const Decoder = struct {
    data: []const u8,
    allocator: Allocator,
    pos: usize = 0,
    indefinite_level: usize = 0, // Track nesting level of indefinite-length items

    /// Initialize a new decoder
    pub fn init(data: []const u8, allocator: Allocator) Decoder {
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Free resources
    pub fn deinit(_: *Decoder) void {
        // Nothing to free
    }

    /// Reset the decoder to be reused with new data
    pub fn reset(self: *Decoder, data: []const u8) void {
        self.data = data;
        self.pos = 0;
        self.indefinite_level = 0;
    }

    /// Get the current position in the data
    pub fn position(self: *const Decoder) usize {
        return self.pos;
    }

    /// Check if we've reached the end of the data
    pub fn isAtEnd(self: *const Decoder) bool {
        return self.pos >= self.data.len;
    }

    /// Get the remaining data
    pub fn remaining(self: *const Decoder) []const u8 {
        if (self.pos >= self.data.len) {
            return &[_]u8{};
        }
        return self.data[self.pos..];
    }

    /// Peek at the major type of the next item
    pub fn peekMajorType(self: *Decoder) !MajorType {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        const byte = self.data[self.pos];
        return MajorType.fromByte(byte);
    }

    /// Peek at the additional info of the next item
    pub fn peekAdditionalInfo(self: *Decoder) !u8 {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        return self.data[self.pos] & 0x1F;
    }

    /// Check if the next item is a break code
    pub fn isBreakCode(self: *Decoder) !bool {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        return self.data[self.pos] == 0xFF;
    }

    /// Read a break code
    pub fn readBreak(self: *Decoder) !void {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        if (self.data[self.pos] != 0xFF) {
            return error.ExpectedBreak;
        }
        self.pos += 1;
        if (self.indefinite_level > 0) {
            self.indefinite_level -= 1;
        }
    }

    /// Begin reading a fixed-length array
    pub fn beginArray(self: *Decoder) !usize {
        const major_type = try self.peekMajorType();
        if (major_type != .Array) {
            return error.ExpectedArray;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            self.indefinite_level += 1;
            return std.math.maxInt(usize); // Indicate indefinite length
        }

        return try self.readAdditionalValue(additional_info);
    }

    /// Begin reading an indefinite-length array
    pub fn beginArrayIndefinite(self: *Decoder) !void {
        const major_type = try self.peekMajorType();
        if (major_type != .Array) {
            return error.ExpectedArray;
        }

        const additional_info = try self.peekAdditionalInfo();
        if (additional_info != AdditionalInfo.INDEFINITE) {
            return error.ExpectedIndefiniteArray;
        }

        self.pos += 1;
        self.indefinite_level += 1;
    }

    /// End reading an array
    pub fn endArray(self: *Decoder) !void {
        // Only needed for indefinite-length arrays
        if (self.indefinite_level > 0) {
            try self.readBreak();
        }
    }

    /// Begin reading a fixed-length map
    pub fn beginMap(self: *Decoder) !usize {
        const major_type = try self.peekMajorType();
        if (major_type != .Map) {
            return error.ExpectedMap;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            self.indefinite_level += 1;
            return std.math.maxInt(usize); // Indicate indefinite length
        }

        return try self.readAdditionalValue(additional_info);
    }

    /// Begin reading an indefinite-length map
    pub fn beginMapIndefinite(self: *Decoder) !void {
        const major_type = try self.peekMajorType();
        if (major_type != .Map) {
            return error.ExpectedMap;
        }

        const additional_info = try self.peekAdditionalInfo();
        if (additional_info != AdditionalInfo.INDEFINITE) {
            return error.ExpectedIndefiniteMap;
        }

        self.pos += 1;
        self.indefinite_level += 1;
    }

    /// End reading a map
    pub fn endMap(self: *Decoder) !void {
        // Only needed for indefinite-length maps
        if (self.indefinite_level > 0) {
            try self.readBreak();
        }
    }

    /// Helper function to read an additional value
    fn readAdditionalValue(self: *Decoder, additional_info: u8) !usize {
        if (additional_info <= AdditionalInfo.DIRECT) {
            return additional_info;
        } else if (additional_info == AdditionalInfo.ONE_BYTE) {
            if (self.pos >= self.data.len) {
                return error.EndOfBuffer;
            }
            const value = self.data[self.pos];
            self.pos += 1;
            return value;
        } else if (additional_info == AdditionalInfo.TWO_BYTES) {
            if (self.pos + 1 >= self.data.len) {
                return error.EndOfBuffer;
            }
            const value = (@as(u16, self.data[self.pos]) << 8) | self.data[self.pos + 1];
            self.pos += 2;
            return value;
        } else if (additional_info == AdditionalInfo.FOUR_BYTES) {
            if (self.pos + 3 >= self.data.len) {
                return error.EndOfBuffer;
            }
            const value = (@as(u32, self.data[self.pos]) << 24) |
                (@as(u32, self.data[self.pos + 1]) << 16) |
                (@as(u32, self.data[self.pos + 2]) << 8) |
                self.data[self.pos + 3];
            self.pos += 4;
            return value;
        } else if (additional_info == AdditionalInfo.EIGHT_BYTES) {
            if (self.pos + 7 >= self.data.len) {
                return error.EndOfBuffer;
            }
            // For simplicity, we'll just use the lower 32 bits for now
            // since usize might not be 64 bits on all platforms
            const value = (@as(u32, self.data[self.pos + 4]) << 24) |
                (@as(u32, self.data[self.pos + 5]) << 16) |
                (@as(u32, self.data[self.pos + 6]) << 8) |
                self.data[self.pos + 7];
            self.pos += 8;
            return value;
        } else {
            return error.UnsupportedAdditionalInfo;
        }
    }

    /// Read a tag
    pub fn readTag(self: *Decoder) !u64 {
        const major_type = try self.peekMajorType();
        if (major_type != .Tag) {
            return error.ExpectedTag;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        return try self.readAdditionalValue(additional_info);
    }

    /// Read a boolean value
    pub fn readBool(self: *Decoder) !bool {
        const major_type = try self.peekMajorType();
        if (major_type != .Simple) {
            return error.ExpectedSimpleValue;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == SimpleValue.TRUE) {
            return true;
        } else if (additional_info == SimpleValue.FALSE) {
            return false;
        } else {
            return error.ExpectedBooleanValue;
        }
    }

    /// Read a null value
    pub fn readNull(self: *Decoder) !void {
        const major_type = try self.peekMajorType();
        if (major_type != .Simple) {
            return error.ExpectedSimpleValue;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info != SimpleValue.NULL) {
            return error.ExpectedNullValue;
        }
    }

    /// Read an undefined value
    pub fn readUndefined(self: *Decoder) !void {
        const major_type = try self.peekMajorType();
        if (major_type != .Simple) {
            return error.ExpectedSimpleValue;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info != SimpleValue.UNDEFINED) {
            return error.ExpectedUndefinedValue;
        }
    }

    /// Read a floating-point value
    pub fn readFloat(self: *Decoder, comptime T: type) !T {
        const major_type = try self.peekMajorType();
        if (major_type != .Simple) {
            return error.ExpectedSimpleValue;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.TWO_BYTES) {
            if (self.pos + 1 >= self.data.len) {
                return error.EndOfBuffer;
            }

            const bits = (@as(u16, self.data[self.pos]) << 8) | self.data[self.pos + 1];
            self.pos += 2;

            const f16_value = @as(f16, @bitCast(bits));

            if (T == f16) {
                return f16_value;
            } else if (T == f32) {
                return @as(f32, @floatCast(f16_value));
            } else if (T == f64) {
                return @as(f64, @floatCast(f16_value));
            } else {
                @compileError("Unsupported float type");
            }
        } else if (additional_info == AdditionalInfo.FOUR_BYTES) {
            if (self.pos + 3 >= self.data.len) {
                return error.EndOfBuffer;
            }

            const bits = (@as(u32, self.data[self.pos]) << 24) |
                (@as(u32, self.data[self.pos + 1]) << 16) |
                (@as(u32, self.data[self.pos + 2]) << 8) |
                self.data[self.pos + 3];
            self.pos += 4;

            const f32_value = @as(f32, @bitCast(bits));

            if (T == f16) {
                return @as(f16, @floatCast(f32_value));
            } else if (T == f32) {
                return f32_value;
            } else if (T == f64) {
                return @as(f64, @floatCast(f32_value));
            } else {
                @compileError("Unsupported float type");
            }
        } else if (additional_info == AdditionalInfo.EIGHT_BYTES) {
            if (self.pos + 7 >= self.data.len) {
                return error.EndOfBuffer;
            }

            const bits = (@as(u64, self.data[self.pos]) << 56) |
                (@as(u64, self.data[self.pos + 1]) << 48) |
                (@as(u64, self.data[self.pos + 2]) << 40) |
                (@as(u64, self.data[self.pos + 3]) << 32) |
                (@as(u64, self.data[self.pos + 4]) << 24) |
                (@as(u64, self.data[self.pos + 5]) << 16) |
                (@as(u64, self.data[self.pos + 6]) << 8) |
                self.data[self.pos + 7];
            self.pos += 8;

            const f64_value = @as(f64, @bitCast(bits));

            if (T == f16) {
                return @as(f16, @floatCast(f64_value));
            } else if (T == f32) {
                return @as(f32, @floatCast(f64_value));
            } else if (T == f64) {
                return f64_value;
            } else {
                @compileError("Unsupported float type");
            }
        } else {
            return error.ExpectedFloatValue;
        }
    }

    /// Read an integer
    pub fn readInt(self: *Decoder, comptime T: type) !T {
        const major_type = try self.peekMajorType();
        if (major_type != .UnsignedInt and major_type != .NegativeInt) {
            return error.ExpectedIntValue;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        const value = try self.readAdditionalValue(additional_info);

        // Handle signed and unsigned types
        if (major_type == .NegativeInt) {
            // For signed types
            if (T == i8 or T == i16 or T == i32 or T == i64 or T == i128 or T == isize) {
                // Convert to negative
                const neg_value = @as(i64, -1) - @as(i64, @intCast(value));
                return @as(T, @intCast(neg_value));
            } else {
                // For unsigned types, we can't represent negative values
                return error.NegativeValueInUnsignedType;
            }
        } else {
            // For positive values, just return the value
            return @as(T, @intCast(value));
        }
    }

    /// Read a byte string
    pub fn readBytes(self: *Decoder, allocator: Allocator) ![]u8 {
        const major_type = try self.peekMajorType();
        if (major_type != .ByteString) {
            return error.ExpectedByteString;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            // Indefinite-length byte string
            self.indefinite_level += 1;

            // For simplicity, we'll just concatenate all chunks
            var result = std.ArrayList(u8){};
            errdefer result.deinit(allocator);

            while (true) {
                if (try self.isBreakCode()) {
                    try self.readBreak();
                    break;
                }

                const chunk = try self.readBytes(allocator);
                defer allocator.free(chunk);

                try result.appendSlice(allocator, chunk);
            }

            return result.toOwnedSlice(allocator);
        } else {
            // Fixed-length byte string
            const len = try self.readAdditionalValue(additional_info);

            if (self.pos + len > self.data.len) {
                return error.EndOfBuffer;
            }

            const result = try allocator.dupe(u8, self.data[self.pos .. self.pos + len]);
            self.pos += len;
            return result;
        }
    }

    /// Read a text string
    pub fn readText(self: *Decoder, allocator: Allocator) ![]u8 {
        const major_type = try self.peekMajorType();
        if (major_type != .TextString) {
            return error.ExpectedTextString;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            // Indefinite-length text string
            self.indefinite_level += 1;

            // For simplicity, we'll just concatenate all chunks
            var result = std.ArrayList(u8){};
            errdefer result.deinit(allocator);

            while (true) {
                if (try self.isBreakCode()) {
                    try self.readBreak();
                    break;
                }

                const chunk = try self.readText(allocator);
                defer allocator.free(chunk);

                try result.appendSlice(allocator, chunk);
            }

            return result.toOwnedSlice(allocator);
        } else {
            // Fixed-length text string
            const len = try self.readAdditionalValue(additional_info);

            if (self.pos + len > self.data.len) {
                return error.EndOfBuffer;
            }

            const result = try allocator.dupe(u8, self.data[self.pos .. self.pos + len]);
            self.pos += len;
            return result;
        }
    }

    /// Skip the next item
    pub fn skip(self: *Decoder) !void {
        const major_type = try self.peekMajorType();
        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        switch (major_type) {
            .UnsignedInt, .NegativeInt => {
                // Skip the value part of the integer
                if (additional_info > AdditionalInfo.DIRECT) {
                    _ = try self.readAdditionalValue(additional_info);
                }
            },
            .ByteString, .TextString => {
                if (additional_info == AdditionalInfo.INDEFINITE) {
                    // Indefinite-length string
                    self.indefinite_level += 1;

                    while (true) {
                        if (try self.isBreakCode()) {
                            try self.readBreak();
                            break;
                        }

                        try self.skip(); // Skip each chunk
                    }
                } else {
                    // Fixed-length string
                    const len = try self.readAdditionalValue(additional_info);

                    if (self.pos + len > self.data.len) {
                        return error.EndOfBuffer;
                    }

                    self.pos += len;
                }
            },
            .Array => {
                if (additional_info == AdditionalInfo.INDEFINITE) {
                    // Indefinite-length array
                    self.indefinite_level += 1;

                    while (true) {
                        if (try self.isBreakCode()) {
                            try self.readBreak();
                            break;
                        }

                        try self.skip(); // Skip each item
                    }
                } else {
                    // Fixed-length array
                    const len = try self.readAdditionalValue(additional_info);

                    for (0..len) |_| {
                        try self.skip(); // Skip each item
                    }
                }
            },
            .Map => {
                if (additional_info == AdditionalInfo.INDEFINITE) {
                    // Indefinite-length map
                    self.indefinite_level += 1;

                    while (true) {
                        if (try self.isBreakCode()) {
                            try self.readBreak();
                            break;
                        }

                        try self.skip(); // Skip key
                        try self.skip(); // Skip value
                    }
                } else {
                    // Fixed-length map
                    const len = try self.readAdditionalValue(additional_info);

                    for (0..len) |_| {
                        try self.skip(); // Skip key
                        try self.skip(); // Skip value
                    }
                }
            },
            .Tag => {
                try self.skip(); // Skip the tagged value
            },
            .Simple => {
                // Skip the value part of the simple value
                if (additional_info == AdditionalInfo.ONE_BYTE) {
                    self.pos += 1;
                } else if (additional_info == AdditionalInfo.TWO_BYTES) {
                    self.pos += 2;
                } else if (additional_info == AdditionalInfo.FOUR_BYTES) {
                    self.pos += 4;
                } else if (additional_info == AdditionalInfo.EIGHT_BYTES) {
                    self.pos += 8;
                }
                // For simple values with additional info <= 23, there's nothing to skip
            },
        }
    }
};
