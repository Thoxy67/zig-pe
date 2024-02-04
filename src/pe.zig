const std = @import("std");
const win = @cImport(@cInclude("windows.h"));

pub const HeadersSizeError = error{
    isNotPe,
    isLessThan64,
    isLessThanRequiredOffset,
    invalidBitVersion,
};

pub const ImageSizeError = error{
    invalidMagic,
    invalidBitVersion,
};

/// Function to get the size of the headers
pub fn get_headers_size(buffer: []u8) HeadersSizeError!usize {
    std.log.debug("\x1b[0;1m[-] === Get DOS Header Size ===\x1b[0m", .{});
    if (buffer.len >= 2 and buffer[0] == 0x4d and buffer[1] == 0x5a) {
        if (buffer.len >= 64) {
            const offset: u32 = std.mem.readVarInt(u32, buffer[60..64], std.builtin.Endian.little);
            if (buffer.len >= offset + 4 + 20 + 2) {
                const bit_version: u16 = std.mem.readVarInt(u16, buffer[offset + 4 + 20 .. offset + 4 + 20 + 2], std.builtin.Endian.little);
                if (bit_version == 523 or bit_version == 267) {
                    const header_size: u32 = std.mem.readVarInt(u32, buffer[offset + 24 + 60 .. offset + 24 + 60 + 4], std.builtin.Endian.little);
                    std.log.debug("dos_header_size\t: \x1b[31m0x{x}\x1b[0m", .{header_size});
                    return @intCast(header_size);
                } else {
                    return error.invalidBitVersion;
                }
            } else {
                return error.isLessThanRequiredOffset;
            }
        } else {
            return error.isLessThan64;
        }
    } else {
        return error.isNotPe;
    }
}

// Function to get the size of the image
pub fn get_image_size(buffer: []u8) ImageSizeError!usize {
    std.log.debug("\x1b[0;1m[-] === Get PE Image Size ===\x1b[0m", .{});
    if (buffer[0] != 0x4d and buffer[1] != 0x5a) {
        return error.invalidMagic;
    }
    const offset: u32 = std.mem.readVarInt(u32, buffer[60..64], std.builtin.Endian.little);
    const bit_version: u32 = std.mem.readVarInt(u32, buffer[(offset + 4 + 20)..(offset + 4 + 20 + 2)], std.builtin.Endian.little);
    if (bit_version == 523 or bit_version == 267) {
        const size: u32 = std.mem.readVarInt(u32, buffer[(offset + 24 + 60 - 4)..((offset + 24 + 60 - 4) + 4)], std.builtin.Endian.little);
        std.log.debug("dos_image_size \t: \x1b[35m0x{x}\x1b[0m", .{size});
        return @intCast(size);
    } else {
        return error.invalidBitVersion;
    }
}

/// Function to get the DOS header
pub fn get_dos_header(lp_image: ?*anyopaque) *win.IMAGE_DOS_HEADER {
    return @ptrCast(@constCast(&lp_image));
}

/// Function to get the NT header
pub fn get_nt_header64(lp_image: ?*anyopaque, lp_dos_header: *win.IMAGE_DOS_HEADER) *win.IMAGE_NT_HEADERS {
    return @as(*win.IMAGE_NT_HEADERS, @ptrFromInt(@intFromPtr(lp_image) + @as(usize, @intCast(lp_dos_header.*.e_lfanew))));
}

/// Writes each section of the PE file to the allocated memory in the target process.
pub fn write_sections(baseptr: ?*anyopaque, buffer: []u8, dos_header: *win.IMAGE_DOS_HEADER, nt_header: *win.IMAGE_NT_HEADERS) void {
    std.log.debug("\x1b[0;1m[-] === Write IMAGE_SECTION_HEADERS ===\x1b[0m", .{});
    for (0..nt_header.*.FileHeader.NumberOfSections) |count| {
        const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(dos_header.*.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS) + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));
        std.log.debug("name : \x1b[32m{s}\x1b[0m\t ptr : \x1b[33m0x{x}\x1b[0m\t size : \x1b[36m{}\x1b[0m", .{ nt_section_header.*.Name, nt_section_header.*.PointerToRawData, nt_section_header.*.SizeOfRawData });
        @memcpy(@as([*]u8, @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(nt_section_header.*.VirtualAddress)))), buffer[(nt_section_header.PointerToRawData + (@sizeOf(win.IMAGE_SECTION_HEADER)))..(nt_section_header.*.PointerToRawData + nt_section_header.*.SizeOfRawData)]);
    }
}
