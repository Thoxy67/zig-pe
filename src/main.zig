const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const file_name = "bin/messagebox.exe";
    var file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize));
    defer gpa.allocator().free(file_content);

    const header_size = try pe.get_headers_size(file_content);
    const header = file_content[0..header_size];

    const image_size = try pe.get_image_size(file_content);

    const addr_alloc: win.LPVOID = try std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE);

    const addr_array_ptr: [*]u8 = @ptrCast(addr_alloc);

    @memcpy(addr_array_ptr[0..header_size], header);

    const dosheader: *const win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_array_ptr));
    const lp_nt_header: *const win.IMAGE_NT_HEADERS = pe.get_nt_header(addr_array_ptr, dosheader);

    pe.write_sections(addr_array_ptr, file_content, dosheader, lp_nt_header);

    try pe.write_import_table(addr_array_ptr, lp_nt_header);

    try pe.fix_base_relocations(addr_array_ptr, lp_nt_header);

    // Change memory protection
    var old_protect: win.DWORD = undefined;
    _ = win.VirtualProtect(addr_alloc, image_size, win.PAGE_EXECUTE_READ, &old_protect);

    // Execute the image
    pe.execute_image(addr_array_ptr, lp_nt_header);

    // Free the allocated memory
    _ = win.VirtualFree(addr_alloc, 0, win.MEM_RELEASE);
}

// FIXME

test "simple test" {}
