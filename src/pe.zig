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
pub fn get_headers_size(buffer: []u8) !usize {
    if (buffer.len >= 2 and buffer[0] == 0x4d and buffer[1] == 0x5a) {
        if (buffer.len >= 64) {
            const offset: u32 = std.mem.readVarInt(u32, buffer[60..64], std.builtin.Endian.little);
            if (buffer.len >= offset + 4 + 20 + 2) {
                const bit_version: u16 = std.mem.readVarInt(u16, buffer[offset + 4 + 20 .. offset + 4 + 20 + 2], std.builtin.Endian.little);
                if (bit_version == 523 or bit_version == 267) {
                    const header_size: u32 = std.mem.readVarInt(u32, buffer[offset + 24 + 60 .. offset + 24 + 60 + 4], std.builtin.Endian.little);
                    std.log.debug("dos_header_size\t= 0x{x}", .{header_size});
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
pub fn get_image_size(buffer: []u8) !usize {
    if (buffer[0] != 0x4d and buffer[1] != 0x5a) {
        return error.invalidMagic;
    }
    const offset: u32 = std.mem.readVarInt(u32, buffer[60..64], std.builtin.Endian.little);
    const bit_version: u32 = std.mem.readVarInt(u32, buffer[(offset + 4 + 20)..(offset + 4 + 20 + 2)], std.builtin.Endian.little);
    if (bit_version == 523 or bit_version == 267) {
        const size: u32 = std.mem.readVarInt(u32, buffer[(offset + 24 + 60 - 4)..((offset + 24 + 60 - 4) + 4)], std.builtin.Endian.little);
        std.log.debug("dos_image_size \t= 0x{x}", .{size});
        return @intCast(size);
    } else {
        return error.invalidBitVersion;
    }
}

/// Function to get the DOS header
pub fn get_dos_header(lp_image: win.LPVOID) *win.IMAGE_DOS_HEADER {
    return @ptrCast(@constCast(&lp_image));
}

/// Function to get the NT header
pub fn get_nt_header64(lp_image: win.LPVOID, lp_dos_header: *win.IMAGE_DOS_HEADER) *win.IMAGE_NT_HEADERS {
    const e_lfanew: usize = @intCast(lp_dos_header.*.e_lfanew);
    const lp_image_ptr = @intFromPtr(lp_image) + e_lfanew;
    return @as(*win.IMAGE_NT_HEADERS, @ptrFromInt(lp_image_ptr));
}

/// Writes each section of the PE file to the allocated memory in the target process.
pub fn write_sections(baseptr: win.LPVOID, buffer: []u8, dos_header: *win.IMAGE_DOS_HEADER, nt_header: *win.IMAGE_NT_HEADERS) void {
    std.log.debug("Write IMAGE_SECTION_HEADER", .{});
    for (0..nt_header.FileHeader.NumberOfSections) |count| {
        const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS) + (count * 40));
        std.log.debug("{s},  {x}", .{ nt_section_header.Name, nt_section_header.PointerToRawData });
        const section_data = buffer[(nt_section_header.PointerToRawData + (@sizeOf(win.IMAGE_SECTION_HEADER)))..(nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData)];
        const VirtualAddress: usize = @intCast(nt_section_header.VirtualAddress);
        const a: [*]u8 = @ptrFromInt(@intFromPtr(baseptr) + VirtualAddress);
        @memcpy(a, section_data);
    }
}
