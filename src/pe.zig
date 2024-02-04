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
pub fn get_dos_header(lp_image: ?*const anyopaque) *win.IMAGE_DOS_HEADER {
    return @ptrCast(@constCast(&lp_image));
}

/// Function to get the NT header
pub fn get_nt_header64(lp_image: ?*const anyopaque, lp_dos_header: *const win.IMAGE_DOS_HEADER) *const win.IMAGE_NT_HEADERS {
    const nt_header: *win.IMAGE_NT_HEADERS = @ptrFromInt(@intFromPtr(lp_image) + @as(usize, @intCast(lp_dos_header.e_lfanew)));
    return nt_header;
}

/// Writes each section of the PE file to the allocated memory in the target process.
pub fn write_sections(baseptr: ?*const anyopaque, buffer: []u8, dos_header: *const win.IMAGE_DOS_HEADER, nt_header: *const win.IMAGE_NT_HEADERS) void {
    std.log.debug("\x1b[0;1m[-] === Write IMAGE_SECTION_HEADERS ===\x1b[0m", .{});
    for (0..nt_header.FileHeader.NumberOfSections) |count| {
        const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS) + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));
        std.log.debug("name : \x1b[32m{s}\x1b[0m\t ptr : \x1b[33m0x{x}\x1b[0m\t size : \x1b[36m{}\x1b[0m", .{ nt_section_header.Name, nt_section_header.PointerToRawData, nt_section_header.SizeOfRawData });
        @memcpy(@as([*]u8, @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(nt_section_header.VirtualAddress)))), buffer[(nt_section_header.PointerToRawData + (@sizeOf(win.IMAGE_SECTION_HEADER)))..(nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData)]);
    }
}

/// Writes the import table of the PE file to the allocated memory in the target process.
pub fn write_import_table(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) void {
    std.log.debug("\x1b[0;1m[-] === Get Write Import Table ===\x1b[0m", .{});
    const import_dir = nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) {
        return;
    }
    var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR =
        @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)) - 40);

    var i: usize = 0;

    while (importDescriptorPtr.Name != 0 and importDescriptorPtr.FirstThunk != 0) {
        const dllNamePtr: [*]u8 =
            @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.Name)) - 40);

        const dllName = read_string_from_memory(dllNamePtr);

        std.log.debug("dll : \x1b[34m{s}\x1b[0m\tfirst_thunk : \x1b[31m0x{x}\x1b[0m\tname_offset: \x1b[32m0x{x}\x1b[0m", .{
            std.mem.span(dllName),
            importDescriptorPtr.FirstThunk,
            importDescriptorPtr.Name - 40,
        });

        // const a: []u8 = (std.mem.span(dllName) ++ 0x0);

        const dll_handle: win.HMODULE = win.LoadLibraryA(read_string_from_memory(dllNamePtr));
        if (dll_handle == null) {
            std.log.err("{s} not found", .{dllName});
            return;
        }
        var thunkptr: usize = @intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.unnamed_0.Characteristics)) - 40;

        while (true) {
            const thunk: [*]u8 = @ptrFromInt(thunkptr);
            const offset: usize = std.mem.readVarInt(usize, thunk[0..@sizeOf(usize)], std.builtin.Endian.little);

            if (offset == 0) {
                break;
            }

            const funcname = read_string_from_memory(@ptrFromInt(@intFromPtr(baseptr) - 40 + offset + 2));
            std.log.debug("function : \x1b[33m{s}\x1b[0m", .{std.mem.span(funcname)});

            const funcaddress: win.FARPROC = win.GetProcAddress(dll_handle, read_string_from_memory(@ptrFromInt(@intFromPtr(baseptr) - 40 + offset + 2)));
            if (funcaddress == null) {
                std.log.err("{s} not found", .{funcname});
                return;
            }

            const funcaddress_ptr: *usize = @ptrFromInt(@intFromPtr(baseptr) - 40 + @as(usize, @intCast(importDescriptorPtr.FirstThunk)) + i * @sizeOf(usize));

            funcaddress_ptr.* = @intCast(@intFromPtr(funcaddress));

            i += 1;
            thunkptr += @sizeOf(usize);
        }

        // Move to the next import descriptor
        importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR));
    }
}

/// Executes the image by calling its entry point and waiting for the thread to finish executing.
pub fn execute_image(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) void {
    const entrypoint: *const fn () void = @ptrFromInt(@intFromPtr(baseptr) - 40 + @as(usize, @intCast(nt_header.OptionalHeader.AddressOfEntryPoint)));
    entrypoint();
}

/// Reads a string from memory.
fn read_string_from_memory(baseptr: [*]u8) [*:0]const u8 {
    var temp: [100]u8 = undefined;
    for (0..100) |i| {
        temp[i] = baseptr[i];
        if (temp[i] == 0) {
            break;
        }
    }
    return temp[0..temp.len :0];
}
