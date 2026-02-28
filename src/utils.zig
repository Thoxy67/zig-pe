const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");
const builtin = @import("builtin");

/// Check if the PE file is a .NET assembly by inspecting the CLR data directory
pub fn is_dotnet_assembly(ntheaders: pe.NtHeaders) bool {
    const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
    const data_dir = ntheaders.dataDirectory();
    return data_dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0;
}

/// Converts an RVA to a raw file offset using the PE section table.
pub fn rvaToFileOffset(buffer: []const u8, rva: u32) ?usize {
    if (buffer.len < 0x40) return null;
    const pe_offset = std.mem.readInt(u32, buffer[0x3C..0x40], .little);
    if (buffer.len < pe_offset + 24) return null;
    const num_sections = std.mem.readInt(u16, buffer[pe_offset + 6 ..][0..2], .little);
    const size_of_opt = std.mem.readInt(u16, buffer[pe_offset + 20 ..][0..2], .little);
    const section_start = pe_offset + 24 + size_of_opt;

    for (0..num_sections) |i| {
        const sh = section_start + i * 40;
        if (buffer.len < sh + 40) return null;
        const virtual_size = std.mem.readInt(u32, buffer[sh + 8 ..][0..4], .little);
        const virtual_addr = std.mem.readInt(u32, buffer[sh + 12 ..][0..4], .little);
        const raw_data_ptr = std.mem.readInt(u32, buffer[sh + 20 ..][0..4], .little);

        if (rva >= virtual_addr and rva < virtual_addr + virtual_size) {
            return @as(usize, rva - virtual_addr + raw_data_ptr);
        }
    }
    return null;
}

/// Extracts the .NET runtime version string from PE metadata.
/// Reads COR20 header -> metadata RVA -> BSJB signature -> version string.
pub fn getDotNetVersion(buffer: []const u8) ?[]const u8 {
    if (buffer.len < 0x40) return null;
    const pe_offset = std.mem.readInt(u32, buffer[0x3C..0x40], .little);
    if (buffer.len < pe_offset + 26) return null;
    const magic = std.mem.readInt(u16, buffer[pe_offset + 24 ..][0..2], .little);

    // DataDirectory offset depends on PE32 vs PE32+
    const data_dir_offset: usize = switch (magic) {
        0x10b => pe_offset + 24 + 96, // PE32
        0x20b => pe_offset + 24 + 112, // PE32+
        else => return null,
    };
    const clr_dir_offset = data_dir_offset + 14 * 8;
    if (buffer.len < clr_dir_offset + 8) return null;

    const cor20_rva = std.mem.readInt(u32, buffer[clr_dir_offset..][0..4], .little);
    if (cor20_rva == 0) return null;

    const cor20_off = rvaToFileOffset(buffer, cor20_rva) orelse return null;
    if (buffer.len < cor20_off + 16) return null;

    // COR20 header: offset +8 = MetaData RVA
    const metadata_rva = std.mem.readInt(u32, buffer[cor20_off + 8 ..][0..4], .little);
    const metadata_off = rvaToFileOffset(buffer, metadata_rva) orelse return null;
    if (buffer.len < metadata_off + 16) return null;

    // Verify BSJB magic
    const bsjb = std.mem.readInt(u32, buffer[metadata_off..][0..4], .little);
    if (bsjb != 0x424A5342) return null;

    // Version string length at offset +12, string at +16
    const ver_len = std.mem.readInt(u32, buffer[metadata_off + 12 ..][0..4], .little);
    if (ver_len == 0 or buffer.len < metadata_off + 16 + ver_len) return null;

    const ver_bytes = buffer[metadata_off + 16 ..][0..ver_len];
    // Trim trailing nulls
    var trimmed_len: usize = ver_len;
    for (ver_bytes, 0..) |b, idx| {
        if (b == 0) {
            trimmed_len = idx;
            break;
        }
    }
    return ver_bytes[0..trimmed_len];
}

/// Detect if the target pe platform is 32 or 64bit
pub fn detect_platform(bytes: []const u8) !u32 {
    if (bytes.len < 0x40 or bytes[0] != 'M' or bytes[1] != 'Z') return error.InvalidPE;
    const pe_offset = std.mem.readInt(u32, bytes[0x3C..0x40], .little);
    if (bytes.len < pe_offset + 6) return error.InvalidMachineTypePE;
    const machine = std.mem.readInt(u16, bytes[pe_offset + 4 ..][0..2], .little);
    return switch (machine) {
        0x014c => 32, // IMAGE_FILE_MACHINE_I386
        0x0200 => 64, // IMAGE_FILE_MACHINE_IA64
        0x8664 => 64, // IMAGE_FILE_MACHINE_AMD64
        0x01C4 => 32, // IMAGE_FILE_MACHINE_ARMNT
        0xAA64 => 64, // IMAGE_FILE_MACHINE_ARM64
        else => error.NotSupportedPlatform,
    };
}

/// Wait for the created thread to complete execution
pub fn waitForThreadCompletion(thread_handle: win.HANDLE) !win.DWORD {
    const wait_result = win.WaitForSingleObject(thread_handle, win.INFINITE);
    switch (wait_result) {
        win.WAIT_OBJECT_0 => {},
        win.WAIT_TIMEOUT => {},
        win.WAIT_FAILED => return error.WaitFailed,
        else => return error.UnexpectedWaitResult,
    }
    var exit_code: win.DWORD = undefined;
    return if (win.GetExitCodeThread(@ptrCast(thread_handle), &exit_code) == 0) error.GetExitCodeFailed else exit_code;
}
