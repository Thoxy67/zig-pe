const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

fn sehFilter(info: *win.EXCEPTION_POINTERS) callconv(.C) i32 {
    const exception = info.ExceptionRecord;
    std.log.err("Exception occurred at address 0x{x}: Code 0x{x}", .{
        @intFromPtr(exception.ExceptionAddress),
        exception.ExceptionCode,
    });
    return win.EXCEPTION_EXECUTE_HANDLER;
}

pub fn main() !void {
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const file_name = "bin/putty.exe";
    const file_content = try std.fs.cwd().readFileAlloc(allocator, file_name, std.math.maxInt(usize));
    defer allocator.free(file_content);

    const header_size = try pe.get_headers_size(file_content);
    const header = file_content[0..header_size];

    const image_size = try pe.get_image_size(file_content);
    const addr_alloc = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE) catch {
        return error.MemoryAllocationFailed;
    };
    defer _ = std.os.windows.VirtualFree(addr_alloc, 0, std.os.windows.MEM_RELEASE);

    const addr_array_ptr: [*]u8 = @ptrCast(addr_alloc);

    // Copy the pe header content content to the allocated memory
    @memcpy(addr_array_ptr[0..header_size], header);

    const dosheader: *win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_array_ptr));
    if (dosheader.e_magic != 0x5A4D) { // "MZ"
        std.log.err("Invalid DOS header", .{});
        return error.InvalidDOSHeader;
    }
    const lp_nt_header: *win.IMAGE_NT_HEADERS = pe.get_nt_header(addr_array_ptr, dosheader);
    if (lp_nt_header.Signature != 0x00004550) { // "PE\0\0"
        std.log.err("Invalid NT header", .{});
        return error.InvalidNTHeader;
    }
    // Write sections, import table, and fix relocations
    try pe.write_sections(addr_array_ptr, file_content, dosheader, lp_nt_header);
    try pe.write_import_table(addr_array_ptr, lp_nt_header);
    try pe.fix_base_relocations(addr_array_ptr, lp_nt_header);
    try pe.validate_pe_structure(addr_array_ptr, lp_nt_header);
    try pe.executeLoadedPE(addr_array_ptr, lp_nt_header);
}
