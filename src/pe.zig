const std = @import("std");
const win = @cImport(@cInclude("windows.h"));

pub const PeError = error{
    InvalidPeSignature,
    InvalidFileSize,
    InvalidBitVersion,
    UnsupportedRelocationType,
    ImportResolutionFailed,
    StringReadError,
};

/// Function to get the size of the headers
pub fn get_headers_size(buffer: []const u8) PeError!usize {
    std.log.debug("\x1b[0;1m[-] === Get DOS Header Size ===\x1b[0m", .{});
    if (buffer.len < 64) return PeError.InvalidFileSize;
    if (buffer[0] != 0x4d or buffer[1] != 0x5a) return PeError.InvalidPeSignature;

    const e_lfanew: u32 = std.mem.readVarInt(u32, buffer[60..64], std.builtin.Endian.little);
    if (buffer.len < e_lfanew + 4 + 20 + 2) return PeError.InvalidFileSize;

    const bit_version: u16 = std.mem.readVarInt(u16, buffer[e_lfanew + 4 + 20 .. e_lfanew + 4 + 20 + 2], std.builtin.Endian.little);
    if (bit_version != 523 and bit_version != 267) return PeError.InvalidBitVersion;

    const header_size: u32 = std.mem.readVarInt(u32, buffer[e_lfanew + 24 + 60 .. e_lfanew + 24 + 60 + 4], std.builtin.Endian.little);
    std.log.debug("dos_header_size\t: \x1b[31m0x{x}\x1b[0m", .{header_size});
    return header_size;
}

/// Function to get the size of the image
pub fn get_image_size(buffer: []const u8) PeError!usize {
    std.log.debug("\x1b[0;1m[-] === Get PE Image Size ===\x1b[0m", .{});
    if (buffer[0] != 0x4d or buffer[1] != 0x5a) return PeError.InvalidPeSignature;

    const e_lfanew: u32 = std.mem.readVarInt(u32, buffer[60..64], std.builtin.Endian.little);
    const bit_version: u16 = std.mem.readVarInt(u16, buffer[e_lfanew + 4 + 20 .. e_lfanew + 4 + 20 + 2], std.builtin.Endian.little);
    if (bit_version != 523 and bit_version != 267) return PeError.InvalidBitVersion;

    const size: u32 = std.mem.readVarInt(u32, buffer[e_lfanew + 24 + 56 .. e_lfanew + 24 + 60], std.builtin.Endian.little);
    std.log.debug("dos_image_size \t: \x1b[35m0x{x}\x1b[0m", .{size});
    return size;
}

/// Function to get the DOS header
pub fn get_dos_header(lp_image: ?*const anyopaque) *const win.IMAGE_DOS_HEADER {
    return @ptrCast(lp_image);
}

/// Function to get the NT header
pub fn get_nt_header(lp_image: ?*const anyopaque, lp_dos_header: *const win.IMAGE_DOS_HEADER) *const win.IMAGE_NT_HEADERS {
    return @ptrFromInt(@intFromPtr(lp_image) + @as(usize, @intCast(lp_dos_header.e_lfanew)));
}

/// Writes each section of the PE file to the allocated memory in the target process.
pub fn write_sections(baseptr: ?*const anyopaque, buffer: []const u8, dos_header: *const win.IMAGE_DOS_HEADER, nt_header: *const win.IMAGE_NT_HEADERS) void {
    std.log.debug("\x1b[0;1m[-] === Write IMAGE_SECTION_HEADERS ===\x1b[0m", .{});
    const section_header_offset = @intFromPtr(baseptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);

    for (0..nt_header.FileHeader.NumberOfSections) |count| {
        const nt_section_header: *const win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));
        std.log.debug("name : \x1b[32m{s}\x1b[0m\t ptr : \x1b[33m0x{x}\x1b[0m\t size : \x1b[36m{}\x1b[0m", .{ nt_section_header.Name, nt_section_header.PointerToRawData, nt_section_header.SizeOfRawData });

        const dest = @as([*]u8, @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(nt_section_header.VirtualAddress))));
        const src = buffer[nt_section_header.PointerToRawData..][0..nt_section_header.SizeOfRawData];
        @memcpy(dest, src);
    }
}

/// Writes the import table of the PE file to the allocated memory in the target process.
pub fn write_import_table(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) PeError!void {
    std.log.debug("\x1b[0;1m[-] === Write Import Table ===\x1b[0m", .{});
    const import_dir = nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) return;

    var importDescriptorPtr: *const win.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)));

    while (importDescriptorPtr.Name != 0 and importDescriptorPtr.FirstThunk != 0) {
        const dllNamePtr = @as([*:0]const u8, @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.Name))));
        const dllName = try read_string_from_memory(dllNamePtr);

        std.log.debug("dll : \x1b[34m{s}\x1b[0m\tfirst_thunk : \x1b[31m0x{x}\x1b[0m\tname_offset: \x1b[32m0x{x}\x1b[0m", .{
            dllName,
            importDescriptorPtr.FirstThunk,
            importDescriptorPtr.Name,
        });

        const dll_handle: win.HMODULE = win.LoadLibraryA(dllName.ptr);
        if (dll_handle == null) {
            std.log.err("{s} not found", .{dllName});
            return PeError.ImportResolutionFailed;
        }
        defer _ = win.FreeLibrary(dll_handle);

        var thunkptr: usize = @intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.FirstThunk));

        var i: usize = 0;
        while (true) {
            const thunk = @as(*align(1) const usize, @ptrFromInt(thunkptr));
            if (thunk.* == 0) break;

            if (thunk.* & (1 << 63) != 0) {
                // Import by ordinal
                const ordinal = @as(u16, @truncate(thunk.* & 0xFFFF));
                const funcaddress = win.GetProcAddress(dll_handle, @ptrFromInt(@as(usize, ordinal)));
                if (funcaddress == null) {
                    std.log.err("Function ordinal {} not found in {s}", .{ ordinal, dllName });
                    return PeError.ImportResolutionFailed;
                }
                const funcaddress_ptr: *usize = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.FirstThunk)) + i * @sizeOf(usize));
                funcaddress_ptr.* = @intFromPtr(funcaddress);
            } else {
                // Import by name
                const name_table_entry = @as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(baseptr) + thunk.*));
                const funcname: [*:0]const u8 = @ptrCast(&name_table_entry.Name[0]);
                const funcaddress = win.GetProcAddress(dll_handle, funcname);
                if (funcaddress == null) {
                    std.log.err("{s} not found in {s}", .{ funcname, dllName });
                    return PeError.ImportResolutionFailed;
                }
                const funcaddress_ptr: *usize = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.FirstThunk)) + i * @sizeOf(usize));
                funcaddress_ptr.* = @intFromPtr(funcaddress);

                std.log.debug("function : \x1b[33m{s}\x1b[0m, ptr: \x1b[30m{*}\x1b[0m, new_ptr: \x1b[32m{?}\x1b[0m", .{ std.mem.span(funcname), funcaddress_ptr, funcaddress });
            }

            i += 1;
            thunkptr += @sizeOf(usize);
        }

        // Move to the next import descriptor
        importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR));
    }
}

/// Fix PE base relocation
fn fix_base_relocations(baseptr: [*]u8, nt_header: *const win.IMAGE_NT_HEADERS) !void {
    std.log.debug("\x1b[0;1m[-] === Fixing Base Relocation Table ===\x1b[0m", .{});

    const delta = @intFromPtr(baseptr) - nt_header.OptionalHeader.ImageBase;
    const reloc_dir = &nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (reloc_dir.Size == 0) {
        return; // No relocations needed
    }

    var reloc_block: *win.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(baseptr + reloc_dir.VirtualAddress));

    while (reloc_block.SizeOfBlock != 0) {
        const entries = @as([*]u16, @ptrCast(@alignCast(reloc_block + 1)))[0 .. (reloc_block.SizeOfBlock - @sizeOf(win.IMAGE_BASE_RELOCATION)) / 2];

        for (entries) |entry| {
            const t = entry >> 12;
            const offset = entry & 0xFFF;

            switch (t) {
                win.IMAGE_REL_BASED_HIGHLOW => {
                    const address = @as(*u32, @ptrCast(@alignCast(baseptr + reloc_block.VirtualAddress + offset)));
                    address.* +%= @truncate(delta);
                },
                win.IMAGE_REL_BASED_DIR64 => {
                    const address = @as(*u64, @ptrCast(@alignCast(baseptr + reloc_block.VirtualAddress + offset)));
                    address.* +%= @as(u64, @bitCast(delta));
                },
                win.IMAGE_REL_BASED_ABSOLUTE => {
                    // Do nothing, it's just for alignment
                },
                else => {
                    return error.UnsupportedRelocationType;
                },
            }
        }

        reloc_block = @as(*win.IMAGE_BASE_RELOCATION, @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc_block)) + reloc_block.SizeOfBlock)));
    }
}

/// Executes the image by calling its entry point
pub fn execute_image(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) void {
    // Note: The subtraction of 40 has been removed as it was unexplained and potentially incorrect
    const entrypoint: *const fn () callconv(.C) void = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(nt_header.OptionalHeader.AddressOfEntryPoint)));
    entrypoint();
}

const COM_DESCRIPTOR_INDEX = 14; // Index in the DataDirectory array

/// Detect whether the PE file is a .NET assembly
pub fn is_dotnet_assembly(nt_headers: *const win.IMAGE_NT_HEADERS) bool {
    const data_directory = &nt_headers.OptionalHeader.DataDirectory[COM_DESCRIPTOR_INDEX];
    return data_directory.VirtualAddress != 0 and data_directory.Size != 0;
}

/// Reads a null-terminated string from memory.
fn read_string_from_memory(baseptr: [*:0]const u8) PeError![]const u8 {
    var len: usize = 0;
    while (baseptr[len] != 0) : (len += 1) {
        if (len >= 1024) {
            return PeError.StringReadError; // Prevent potential infinite loop
        }
    }
    return baseptr[0..len];
}
