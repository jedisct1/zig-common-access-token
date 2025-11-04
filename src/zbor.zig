///! CBOR encoder/decoder per RFC 8949
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const MajorType = enum(u3) {
    UnsignedInt = 0,
    NegativeInt = 1,
    ByteString = 2,
    TextString = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    Simple = 7,

    pub fn fromByte(byte: u8) MajorType {
        return @enumFromInt((byte >> 5) & 0x7);
    }

    /// Returns the type byte with additional info set to 0
    pub fn toByte(self: MajorType) u8 {
        return @as(u8, @intFromEnum(self)) << 5;
    }
};

pub const AdditionalInfo = struct {
    pub const DIRECT: u8 = 23;
    pub const ONE_BYTE: u8 = 24;
    pub const TWO_BYTES: u8 = 25;
    pub const FOUR_BYTES: u8 = 26;
    pub const EIGHT_BYTES: u8 = 27;
    pub const INDEFINITE: u8 = 31;
};

pub const SimpleValue = struct {
    pub const FALSE: u8 = 20;
    pub const TRUE: u8 = 21;
    pub const NULL: u8 = 22;
    pub const UNDEFINED: u8 = 23;
};

pub const Encoder = struct {
    allocator: Allocator,
    buffer: std.ArrayList(u8),
    indefinite_level: usize = 0,

    pub fn init(allocator: Allocator) Encoder {
        return initCapacity(allocator, 256);
    }

    pub fn initCapacity(allocator: Allocator, capacity: usize) Encoder {
        return .{
            .allocator = allocator,
            .buffer = std.ArrayList(u8).initCapacity(allocator, capacity) catch
                std.ArrayList(u8){},
        };
    }

    pub fn deinit(self: *Encoder) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn reset(self: *Encoder) void {
        self.buffer.clearRetainingCapacity();
        self.indefinite_level = 0;
    }

    pub fn len(self: *const Encoder) usize {
        return self.buffer.items.len;
    }

    pub fn beginArray(self: *Encoder, length: usize) !void {
        try self.writeTypeAndValue(MajorType.Array, length);
    }

    pub fn beginArrayIndefinite(self: *Encoder) !void {
        try self.buffer.append(self.allocator, MajorType.Array.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    pub fn endArray(self: *Encoder) !void {
        try self.endContainer();
    }

    fn endContainer(self: *Encoder) !void {
        if (self.indefinite_level > 0) {
            try self.buffer.append(self.allocator, 0xFF);
            self.indefinite_level -= 1;
        }
    }

    pub fn beginMap(self: *Encoder, length: usize) !void {
        try self.writeTypeAndValue(MajorType.Map, length);
    }

    pub fn beginMapIndefinite(self: *Encoder) !void {
        try self.buffer.append(self.allocator, MajorType.Map.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    pub fn endMap(self: *Encoder) !void {
        try self.endContainer();
    }
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
            try self.buffer.append(self.allocator, type_byte | @as(u8, @intCast(unsigned_value)));
        } else if (unsigned_value <= std.math.maxInt(u8)) {
            try self.buffer.append(self.allocator, type_byte | AdditionalInfo.ONE_BYTE);
            try self.buffer.append(self.allocator, @as(u8, @intCast(unsigned_value)));
        } else if (unsigned_value <= std.math.maxInt(u16)) {
            try self.buffer.append(self.allocator, type_byte | AdditionalInfo.TWO_BYTES);
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, @intCast(unsigned_value), .big);
            try self.buffer.appendSlice(self.allocator, &buf);
        } else if (unsigned_value <= std.math.maxInt(u32)) {
            try self.buffer.append(self.allocator, type_byte | AdditionalInfo.FOUR_BYTES);
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, @intCast(unsigned_value), .big);
            try self.buffer.appendSlice(self.allocator, &buf);
        } else {
            try self.buffer.append(self.allocator, type_byte | AdditionalInfo.EIGHT_BYTES);
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, @intCast(unsigned_value), .big);
            try self.buffer.appendSlice(self.allocator, &buf);
        }
    }

    pub fn pushInt(self: *Encoder, value: anytype) !void {
        if (value >= 0) {
            try self.writeTypeAndValue(MajorType.UnsignedInt, value);
        } else {
            const abs_value = @as(u64, @intCast(-(value + 1)));
            try self.writeTypeAndValue(MajorType.NegativeInt, abs_value);
        }
    }

    pub fn pushBool(self: *Encoder, value: bool) !void {
        try self.buffer.append(self.allocator, MajorType.Simple.toByte() | (if (value) SimpleValue.TRUE else SimpleValue.FALSE));
    }

    pub fn pushNull(self: *Encoder) !void {
        try self.buffer.append(self.allocator, MajorType.Simple.toByte() | SimpleValue.NULL);
    }

    pub fn pushUndefined(self: *Encoder) !void {
        try self.buffer.append(self.allocator, MajorType.Simple.toByte() | SimpleValue.UNDEFINED);
    }

    pub fn pushFloat(self: *Encoder, value: anytype) !void {
        const T = @TypeOf(value);

        if (T == f16) {
            try self.buffer.append(self.allocator, MajorType.Simple.toByte() | AdditionalInfo.TWO_BYTES);
            const bits = @as(u16, @bitCast(value));
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, bits, .big);
            try self.buffer.appendSlice(self.allocator, &buf);
        } else if (T == f32) {
            try self.buffer.append(self.allocator, MajorType.Simple.toByte() | AdditionalInfo.FOUR_BYTES);
            const bits = @as(u32, @bitCast(value));
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &buf, bits, .big);
            try self.buffer.appendSlice(self.allocator, &buf);
        } else if (T == f64) {
            try self.buffer.append(self.allocator, MajorType.Simple.toByte() | AdditionalInfo.EIGHT_BYTES);
            const bits = @as(u64, @bitCast(value));
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, bits, .big);
            try self.buffer.appendSlice(self.allocator, &buf);
        } else {
            @compileError("Unsupported type for pushFloat");
        }
    }

    pub fn pushBytes(self: *Encoder, bytes: []const u8) !void {
        try self.writeTypeAndValue(MajorType.ByteString, bytes.len);
        try self.buffer.appendSlice(self.allocator, bytes);
    }

    pub fn pushBytesIndefinite(self: *Encoder) !void {
        try self.pushIndefiniteString(MajorType.ByteString);
    }

    pub fn pushText(self: *Encoder, text: []const u8) !void {
        try self.writeTypeAndValue(MajorType.TextString, text.len);
        try self.buffer.appendSlice(self.allocator, text);
    }

    pub fn pushTextIndefinite(self: *Encoder) !void {
        try self.pushIndefiniteString(MajorType.TextString);
    }

    fn pushIndefiniteString(self: *Encoder, major_type: MajorType) !void {
        try self.buffer.append(self.allocator, major_type.toByte() | AdditionalInfo.INDEFINITE);
        self.indefinite_level += 1;
    }

    pub fn pushTag(self: *Encoder, tag: u64) !void {
        try self.writeTypeAndValue(MajorType.Tag, tag);
    }

    pub fn pushBreak(self: *Encoder) !void {
        try self.buffer.append(self.allocator, 0xFF);
        if (self.indefinite_level > 0) {
            self.indefinite_level -= 1;
        }
    }

    pub fn pushRaw(self: *Encoder, data: []const u8) !void {
        try self.buffer.appendSlice(self.allocator, data);
    }

    /// Returns slice valid until encoder is modified or freed
    pub fn finish(self: *Encoder) []const u8 {
        return self.buffer.items;
    }
};

pub const Decoder = struct {
    data: []const u8,
    allocator: Allocator,
    pos: usize = 0,
    indefinite_level: usize = 0,

    pub fn init(data: []const u8, allocator: Allocator) Decoder {
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn deinit(_: *Decoder) void {}

    pub fn reset(self: *Decoder, data: []const u8) void {
        self.data = data;
        self.pos = 0;
        self.indefinite_level = 0;
    }

    pub fn position(self: *const Decoder) usize {
        return self.pos;
    }

    pub fn isAtEnd(self: *const Decoder) bool {
        return self.pos >= self.data.len;
    }

    pub fn remaining(self: *const Decoder) []const u8 {
        if (self.pos >= self.data.len) {
            return &[_]u8{};
        }
        return self.data[self.pos..];
    }

    pub fn peekMajorType(self: *Decoder) !MajorType {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        const byte = self.data[self.pos];
        return MajorType.fromByte(byte);
    }

    pub fn peekAdditionalInfo(self: *Decoder) !u8 {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        return self.data[self.pos] & 0x1F;
    }

    pub fn isBreakCode(self: *Decoder) !bool {
        if (self.pos >= self.data.len) {
            return error.EndOfBuffer;
        }
        return self.data[self.pos] == 0xFF;
    }

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

    pub fn beginArray(self: *Decoder) !usize {
        const major_type = try self.peekMajorType();
        if (major_type != .Array) {
            return error.ExpectedArray;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            self.indefinite_level += 1;
            return std.math.maxInt(usize);
        }

        return try self.readAdditionalValue(additional_info);
    }

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

    pub fn endArray(self: *Decoder) !void {
        try self.endContainer();
    }

    pub fn beginMap(self: *Decoder) !usize {
        const major_type = try self.peekMajorType();
        if (major_type != .Map) {
            return error.ExpectedMap;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            self.indefinite_level += 1;
            return std.math.maxInt(usize);
        }

        return try self.readAdditionalValue(additional_info);
    }

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

    pub fn endMap(self: *Decoder) !void {
        try self.endContainer();
    }

    fn endContainer(self: *Decoder) !void {
        if (self.indefinite_level > 0) {
            try self.readBreak();
        }
    }

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
            const value = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
            self.pos += 2;
            return value;
        } else if (additional_info == AdditionalInfo.FOUR_BYTES) {
            if (self.pos + 3 >= self.data.len) {
                return error.EndOfBuffer;
            }
            const value = std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
            self.pos += 4;
            return value;
        } else if (additional_info == AdditionalInfo.EIGHT_BYTES) {
            if (self.pos + 7 >= self.data.len) {
                return error.EndOfBuffer;
            }
            const full_value = std.mem.readInt(u64, self.data[self.pos..][0..8], .big);
            self.pos += 8;
            return @intCast(full_value & 0xFFFFFFFF);
        } else {
            return error.UnsupportedAdditionalInfo;
        }
    }

    pub fn readTag(self: *Decoder) !u64 {
        const major_type = try self.peekMajorType();
        if (major_type != .Tag) {
            return error.ExpectedTag;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        return try self.readAdditionalValue(additional_info);
    }

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

            const bits = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
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

            const bits = std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
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

            const bits = std.mem.readInt(u64, self.data[self.pos..][0..8], .big);
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

    pub fn readInt(self: *Decoder, comptime T: type) !T {
        const major_type = try self.peekMajorType();
        if (major_type != .UnsignedInt and major_type != .NegativeInt) {
            return error.ExpectedIntValue;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        const value = try self.readAdditionalValue(additional_info);

        if (major_type == .NegativeInt) {
            if (T == i8 or T == i16 or T == i32 or T == i64 or T == i128 or T == isize) {
                const neg_value = @as(i64, -1) - @as(i64, @intCast(value));
                return @as(T, @intCast(neg_value));
            } else {
                return error.NegativeValueInUnsignedType;
            }
        } else {
            return @as(T, @intCast(value));
        }
    }

    pub fn readBytes(self: *Decoder, allocator: Allocator) ![]u8 {
        const major_type = try self.peekMajorType();
        if (major_type != .ByteString) {
            return error.ExpectedByteString;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            self.indefinite_level += 1;

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
            const len = try self.readAdditionalValue(additional_info);

            if (self.pos + len > self.data.len) {
                return error.EndOfBuffer;
            }

            const result = try allocator.dupe(u8, self.data[self.pos .. self.pos + len]);
            self.pos += len;
            return result;
        }
    }

    pub fn readText(self: *Decoder, allocator: Allocator) ![]u8 {
        const major_type = try self.peekMajorType();
        if (major_type != .TextString) {
            return error.ExpectedTextString;
        }

        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        if (additional_info == AdditionalInfo.INDEFINITE) {
            self.indefinite_level += 1;

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
            const len = try self.readAdditionalValue(additional_info);

            if (self.pos + len > self.data.len) {
                return error.EndOfBuffer;
            }

            const result = try allocator.dupe(u8, self.data[self.pos .. self.pos + len]);
            self.pos += len;
            return result;
        }
    }

    pub fn skip(self: *Decoder) !void {
        const major_type = try self.peekMajorType();
        const additional_info = try self.peekAdditionalInfo();
        self.pos += 1;

        switch (major_type) {
            .UnsignedInt, .NegativeInt => {
                if (additional_info > AdditionalInfo.DIRECT) {
                    _ = try self.readAdditionalValue(additional_info);
                }
            },
            .ByteString, .TextString => {
                if (additional_info == AdditionalInfo.INDEFINITE) {
                    self.indefinite_level += 1;

                    while (true) {
                        if (try self.isBreakCode()) {
                            try self.readBreak();
                            break;
                        }

                        try self.skip();
                    }
                } else {
                    const len = try self.readAdditionalValue(additional_info);

                    if (self.pos + len > self.data.len) {
                        return error.EndOfBuffer;
                    }

                    self.pos += len;
                }
            },
            .Array => {
                if (additional_info == AdditionalInfo.INDEFINITE) {
                    self.indefinite_level += 1;

                    while (true) {
                        if (try self.isBreakCode()) {
                            try self.readBreak();
                            break;
                        }

                        try self.skip();
                    }
                } else {
                    const len = try self.readAdditionalValue(additional_info);

                    for (0..len) |_| {
                        try self.skip();
                    }
                }
            },
            .Map => {
                if (additional_info == AdditionalInfo.INDEFINITE) {
                    self.indefinite_level += 1;

                    while (true) {
                        if (try self.isBreakCode()) {
                            try self.readBreak();
                            break;
                        }

                        try self.skip();
                        try self.skip();
                    }
                } else {
                    const len = try self.readAdditionalValue(additional_info);

                    for (0..len) |_| {
                        try self.skip();
                        try self.skip();
                    }
                }
            },
            .Tag => {
                try self.skip();
            },
            .Simple => {
                if (additional_info == AdditionalInfo.ONE_BYTE) {
                    self.pos += 1;
                } else if (additional_info == AdditionalInfo.TWO_BYTES) {
                    self.pos += 2;
                } else if (additional_info == AdditionalInfo.FOUR_BYTES) {
                    self.pos += 4;
                } else if (additional_info == AdditionalInfo.EIGHT_BYTES) {
                    self.pos += 8;
                }
            },
        }
    }
};
