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
pub fn get_dos_header(lp_image: ?*anyopaque) *win.IMAGE_DOS_HEADER {
    return @ptrCast(lp_image);
}

/// Function to get the NT header
pub fn get_nt_header(lp_image: ?*anyopaque, lp_dos_header: *win.IMAGE_DOS_HEADER) *win.IMAGE_NT_HEADERS {
    return @ptrFromInt(@intFromPtr(lp_image) + @as(usize, @intCast(lp_dos_header.e_lfanew)));
}

/// Writes each section of the PE file to the allocated memory in the target process.
pub fn write_sections(baseptr: [*]u8, buffer: []const u8, dos_header: *win.IMAGE_DOS_HEADER, nt_header: *win.IMAGE_NT_HEADERS) !void {
    std.log.debug("\x1b[0;1m[-] === Writing sections header ===\x1b[0m", .{});
    const section_header_offset = @intFromPtr(baseptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);

    for (0..nt_header.FileHeader.NumberOfSections) |count| {
        const nt_section_header: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (count * @sizeOf(win.IMAGE_SECTION_HEADER)));

        std.log.debug("Section: \x1b[32m{s}\x1b[0m\t VirtualAddress: \x1b[33m0x{x}\x1b[0m\t PointerToRawData: \x1b[36m0x{x}\x1b[0m\t SizeOfRawData: \x1b[35m{}\x1b[0m", .{
            nt_section_header.Name,
            nt_section_header.VirtualAddress,
            nt_section_header.PointerToRawData,
            nt_section_header.SizeOfRawData,
        });

        if (nt_section_header.PointerToRawData == 0 or nt_section_header.SizeOfRawData == 0) {
            std.log.debug("Skipping section with no raw data", .{});
            continue;
        }

        if (nt_section_header.PointerToRawData + nt_section_header.SizeOfRawData > buffer.len) {
            std.log.err("Section data exceeds buffer size", .{});
            return error.SectionOutOfBounds;
        }

        const dest = baseptr + nt_section_header.VirtualAddress;
        const src = buffer[nt_section_header.PointerToRawData..][0..nt_section_header.SizeOfRawData];

        @memcpy(dest[0..src.len], src);
    }
}

/// Writes the import table of the PE file to the allocated memory in the target process.
pub fn write_import_table(baseptr: ?*anyopaque, nt_header: *win.IMAGE_NT_HEADERS) PeError!void {
    std.log.debug("\x1b[0;1m[-] === Write Import Table ===\x1b[0m", .{});
    const import_dir = nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) return;

    var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)));

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
        defer std.os.windows.FreeLibrary(@ptrCast(dll_handle.?));

        var thunkptr: usize = @intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.FirstThunk));

        var i: usize = 0;
        while (true) {
            const thunk = @as(*align(1) const usize, @ptrFromInt(thunkptr));
            if (thunk.* == 0) break;

            const original_thunk_value = thunk.*;
            const funcaddress_ptr: *usize = @ptrFromInt(thunkptr);
            const old_ptr_value = funcaddress_ptr.*;

            if (original_thunk_value & (1 << 63) != 0) {
                // Import by ordinal
                const ordinal = @as(u16, @truncate(original_thunk_value & 0xFFFF));
                const funcaddress = std.os.windows.kernel32.GetProcAddress(@ptrCast(dll_handle), @ptrFromInt(@as(usize, ordinal)));
                if (funcaddress == null) {
                    std.log.err("Function ordinal {} not found in {s}", .{ ordinal, dllName });
                    return PeError.ImportResolutionFailed;
                }
                funcaddress_ptr.* = @intFromPtr(funcaddress);
                std.log.debug("function ordinal : \x1b[33m{}\x1b[0m, old_ptr: \x1b[31m0x{x}\x1b[0m, new_ptr: \x1b[32m0x{x}\x1b[0m", .{ ordinal, old_ptr_value, @intFromPtr(funcaddress) });
            } else {
                // Import by name
                const name_table_entry = @as(*align(1) const win.IMAGE_IMPORT_BY_NAME, @ptrFromInt(@intFromPtr(baseptr) + original_thunk_value));
                const funcname: [*:0]const u8 = @ptrCast(&name_table_entry.Name[0]);
                const funcaddress = std.os.windows.kernel32.GetProcAddress(@ptrCast(dll_handle), funcname);
                if (funcaddress == null) {
                    std.log.err("{s} not found in {s}", .{ funcname, dllName });
                    return PeError.ImportResolutionFailed;
                }
                funcaddress_ptr.* = @intFromPtr(funcaddress);
                std.log.debug("function : \x1b[33m{s}\x1b[0m, old_ptr: \x1b[31m0x{x}\x1b[0m, new_ptr: \x1b[32m0x{x}\x1b[0m", .{ std.mem.span(funcname), old_ptr_value, @intFromPtr(funcaddress) });
            }

            i += 1;
            thunkptr += @sizeOf(usize);
        }

        // Move to the next import descriptor
        importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR));
    }
}

/// Fix PE base relocation
pub fn fix_base_relocations(baseptr: [*]u8, nt_header: *win.IMAGE_NT_HEADERS) !void {
    std.log.debug("\x1b[0;1m[-] === Fixing Base Relocation Table ===\x1b[0m", .{});

    const delta = @intFromPtr(baseptr) - nt_header.OptionalHeader.ImageBase;
    std.log.debug("Relocation delta: 0x{x}", .{delta});

    const reloc_dir = &nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC];
    std.log.debug("Relocation directory VirtualAddress: 0x{x}, Size: {}", .{ reloc_dir.VirtualAddress, reloc_dir.Size });

    if (reloc_dir.Size == 0) {
        std.log.info("No relocations needed", .{});
        return;
    }

    var reloc_block: *win.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(baseptr + reloc_dir.VirtualAddress));
    var block_count: usize = 0;

    while (reloc_block.SizeOfBlock != 0) {
        std.log.debug("Processing relocation block {}: VirtualAddress: 0x{x}, SizeOfBlock: {}", .{
            block_count,
            reloc_block.VirtualAddress,
            reloc_block.SizeOfBlock,
        });

        const entries = @as([*]u16, @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc_block)) + @sizeOf(win.IMAGE_BASE_RELOCATION))))[0 .. (reloc_block.SizeOfBlock - @sizeOf(win.IMAGE_BASE_RELOCATION)) / 2];

        for (entries, 0..) |entry, i| {
            const t = entry >> 12;
            const offset = entry & 0xFFF;
            //_ = i;

            std.log.debug("  Entry {}: Type: {}, Offset: 0x{x}", .{ i, t, offset });

            switch (t) {
                win.IMAGE_REL_BASED_HIGHLOW => {
                    const address = @as(*u32, @ptrCast(@alignCast(baseptr + reloc_block.VirtualAddress + offset)));
                    const old_value = address.*;
                    address.* +%= @truncate(delta);
                    std.log.debug("    HIGHLOW: Old value: 0x{x}, New value: 0x{x}", .{ old_value, address.* });
                },
                win.IMAGE_REL_BASED_DIR64 => {
                    const address = @as(*u64, @ptrCast(@alignCast(baseptr + reloc_block.VirtualAddress + offset)));
                    const old_value = address.*;
                    address.* +%= @as(u64, @bitCast(delta));
                    std.log.debug("    DIR64: Old value: 0x{x}, New value: 0x{x}", .{ old_value, address.* });
                },
                win.IMAGE_REL_BASED_ABSOLUTE => {
                    std.log.debug("    ABSOLUTE: No action needed", .{});
                },
                else => {
                    std.log.err("Unsupported relocation type: {}", .{t});
                    return error.UnsupportedRelocationType;
                },
            }
        }

        reloc_block = @as(*win.IMAGE_BASE_RELOCATION, @ptrCast(@alignCast(@as([*]u8, @ptrCast(reloc_block)) + reloc_block.SizeOfBlock)));
        block_count += 1;
    }

    std.log.info("Base relocations fixed. Processed {} blocks.", .{block_count});
}

/// Executes the image by calling its entry point
pub fn execute_image(baseptr: ?*anyopaque, nt_header: *win.IMAGE_NT_HEADERS) void {
    // Note: The subtraction of 40 has been removed as it was unexplained and potentially incorrect
    const entrypoint: *fn () callconv(.C) void = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(nt_header.OptionalHeader.AddressOfEntryPoint)));
    entrypoint();
}

const COM_DESCRIPTOR_INDEX = 14; // Index in the DataDirectory array

/// Detect whether the PE file is a .NET assembly
pub fn is_dotnet_assembly(nt_headers: *win.IMAGE_NT_HEADERS) bool {
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

fn logMemoryContents(addr: [*]u8, size: usize) void {
    std.log.info("Memory contents at 0x{x}:", .{(@ptrFromInt(addr))});
    for (addr[0..size], 0..) |byte, i| {
        if (i % 16 == 0) std.log.info("\n{x:0>8}: ", .{i});
        std.log.info("{x:0>2} ", .{byte});
    }
    std.log.info("\n", .{});
}

pub fn validate_pe_structure(baseptr: [*]u8, nt_header: *win.IMAGE_NT_HEADERS) !void {
    std.log.info("Validating PE structure...", .{});

    // Check section alignment
    if (nt_header.OptionalHeader.SectionAlignment == 0 or nt_header.OptionalHeader.FileAlignment == 0) {
        std.log.err("Invalid section or file alignment", .{});
        return error.InvalidAlignment;
    }

    // Validate sections
    const dos_header = @as(*win.IMAGE_DOS_HEADER, @alignCast(@ptrCast(baseptr)));
    const section_header_offset = @intFromPtr(baseptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);

    for (0..nt_header.FileHeader.NumberOfSections) |i| {
        const section: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (i * @sizeOf(win.IMAGE_SECTION_HEADER)));
        if (section.VirtualAddress + section.Misc.VirtualSize > nt_header.OptionalHeader.SizeOfImage) {
            std.log.err("Section {} extends beyond image size", .{i});
            return error.InvalidSectionSize;
        }
    }

    // Check entry point
    if (nt_header.OptionalHeader.AddressOfEntryPoint >= nt_header.OptionalHeader.SizeOfImage) {
        std.log.err("Entry point is outside the image", .{});
        return error.InvalidEntryPoint;
    }

    std.log.info("PE structure validation completed", .{});
}

fn changeMemoryProtection(addr_array_ptr: [*]u8, nt_header: *win.IMAGE_NT_HEADERS) !void {
    var old_protect: std.os.windows.DWORD = undefined;
    const dos_header = @as(*win.IMAGE_DOS_HEADER, @ptrCast(@alignCast(addr_array_ptr)));
    const section_header_offset = @intFromPtr(addr_array_ptr) + @as(usize, @intCast(dos_header.e_lfanew)) + @sizeOf(win.IMAGE_NT_HEADERS);

    for (0..nt_header.FileHeader.NumberOfSections) |i| {
        const section: *win.IMAGE_SECTION_HEADER = @ptrFromInt(section_header_offset + (i * @sizeOf(win.IMAGE_SECTION_HEADER)));
        const section_addr = @as([*]u8, @ptrCast(addr_array_ptr)) + section.VirtualAddress;
        const section_size = section.Misc.VirtualSize;
        const characteristics = section.Characteristics;

        var new_protect: std.os.windows.DWORD = std.os.windows.PAGE_READONLY;
        if (characteristics & win.IMAGE_SCN_MEM_EXECUTE != 0) {
            new_protect = std.os.windows.PAGE_EXECUTE_READ;
        }
        if (characteristics & win.IMAGE_SCN_MEM_WRITE != 0) {
            new_protect = std.os.windows.PAGE_READWRITE;
        }
        if (characteristics & win.IMAGE_SCN_MEM_EXECUTE != 0 and characteristics & win.IMAGE_SCN_MEM_WRITE != 0) {
            new_protect = std.os.windows.PAGE_EXECUTE_READWRITE;
        }

        std.log.info("Changing protection for section {}: 0x{x} to 0x{x}", .{ i, @intFromPtr(section_addr), new_protect });
        try std.os.windows.VirtualProtect(section_addr, section_size, new_protect, &old_protect);
    }
}

fn createAndRunThread(addr_array_ptr: [*]u8, nt_header: *win.IMAGE_NT_HEADERS) !win.HANDLE {
    const entry_point_addr = @intFromPtr(addr_array_ptr) + nt_header.OptionalHeader.AddressOfEntryPoint;
    const entry_point: std.os.windows.LPTHREAD_START_ROUTINE = @ptrCast(@alignCast(@as(*const fn () callconv(.C) void, @ptrFromInt(entry_point_addr))));

    const thread_handle = std.os.windows.kernel32.CreateThread(null, 0, entry_point, null, 0, null);

    if (thread_handle == null) {
        std.log.err("Failed to create thread: {}", .{std.os.windows.kernel32.GetLastError()});
        return error.ThreadCreationFailed;
    }

    return thread_handle.?;
}

fn waitForThreadCompletion(thread_handle: win.HANDLE) !win.DWORD {
    const wait_result = win.WaitForSingleObject(thread_handle.?, win.INFINITE);
    switch (wait_result) {
        win.WAIT_OBJECT_0 => std.log.info("Thread finished execution", .{}),
        win.WAIT_TIMEOUT => std.log.warn("Thread execution timed out", .{}),
        win.WAIT_FAILED => {
            std.log.err("WaitForSingleObject failed: {}", .{win.GetLastError()});
            return error.WaitFailed;
        },
        else => {
            std.log.err("Unexpected wait result: {}", .{wait_result});
            return error.UnexpectedWaitResult;
        },
    }
    var exit_code: win.DWORD = undefined;
    if (win.GetExitCodeThread(thread_handle.?, &exit_code) == 0) {
        std.log.err("Failed to get thread exit code: {}", .{win.GetLastError()});
        return error.GetExitCodeFailed;
    }

    return exit_code;
}

pub fn executeLoadedPE(addr_array_ptr: [*]u8, nt_header: *win.IMAGE_NT_HEADERS) !void {
    try changeMemoryProtection(addr_array_ptr, nt_header);

    const thread_handle = try createAndRunThread(addr_array_ptr, nt_header);
    defer std.os.windows.CloseHandle(thread_handle.?);

    const exit_code = try waitForThreadCompletion(thread_handle);
    std.log.info("Thread exited with code: {}", .{exit_code});
    std.log.info("Execution completed.", .{});
}
