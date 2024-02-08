const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const file_name = "bin/messagebox.exe"; // Ok
    var file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize)); // Ok

    // Ok
    const header_size = pe.get_headers_size(file_content) catch |e| {
        std.log.err("cannot get header size : {}\n", .{e});
        return e;
    };
    const header = file_content[0..header_size]; // Ok

    // Ok
    const image_size = pe.get_image_size(file_content) catch |e| {
        std.log.err("cannot get image size : {}\n", .{e});
        return e;
    };

    // Ok
    const addr_alloc: win.LPVOID = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE) catch |e| {
        std.log.err("cannot alloc virtual memory {}\n", .{e});
        return e;
    };

    const addr_array_ptr: [*]u8 = @ptrCast(addr_alloc); // Ok

    @memcpy(addr_array_ptr, header); // Ok

    const dosheader: *const win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_array_ptr)); // Ok
    const lp_nt_header: *const win.IMAGE_NT_HEADERS = pe.get_nt_header(addr_array_ptr, dosheader); // Ok

    pe.write_sections(addr_array_ptr, file_content, dosheader, lp_nt_header); // Ok

    pe.write_import_table(addr_array_ptr, lp_nt_header); // I don't know but seems Ok

    fix_base_relocations(addr_array_ptr, lp_nt_header); // Not Ok

    //pe.execute_image(addr_array_ptr, lp_nt_header); // I can't test without fixing base relocations
}

// FIXME
fn fix_base_relocations(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) void {
    _ = baseptr;
    std.log.debug("\x1b[0;1m[-] === Fixing Base Relocation Table ===\x1b[0m", .{});

    //const delta: *usize = @ptrFromInt(@intFromPtr(baseptr) - nt_header.*.OptionalHeader.ImageBase);
    const optionalHeader = nt_header.*.OptionalHeader;
    _ = optionalHeader;
    //const relocationDirRVA: u32 = optionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    // const relocationDirSize: u32 = optionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    // var base_ptr: usize = @intFromPtr(@as(*win.IMAGE_BASE_RELOCATION, @ptrFromInt(@intFromPtr(baseptr) + relocationDirRVA)));
    // std.debug.print("Optional Header Base: {x}\n", .{optionalHeader.ImageBase});
    // std.debug.print("Relocation RVA: {x}, Size: {x}, Base: {x}\n", .{ relocationDirRVA, relocationDirSize, base_ptr });

    // var base: *const win.IMAGE_BASE_RELOCATION = @as(*win.IMAGE_BASE_RELOCATION, @ptrFromInt(base_ptr));

    // while (base.*.SizeOfBlock != 0) {
    //     if (base.*.SizeOfBlock == 0) {
    //         break;
    //     }
    //     const entries_count: u32 = (base.SizeOfBlock - 8) / 2;

    //     std.debug.print("Entries Count: {x}\n", .{entries_count});

    //     for (0..entries_count) |i| {
    //         const offset: *const u16 = @ptrFromInt(base_ptr + @sizeOf(win.IMAGE_BASE_RELOCATION) + (i * 2));

    //         if (offset.* >> 12 != win.IMAGE_REL_BASED_ABSOLUTE) {
    //             const pagerva: u16 = offset.* & 0x0fff;
    //             std.debug.print("Offset: {x}, Offset_Page: {x}\n", .{ offset.*, pagerva });

    //             const finaladdress: *usize = @ptrFromInt(base_ptr + base.*.VirtualAddress + (offset.* & 0x0fff));
    //             std.debug.print("Final Address: {*}\n", .{finaladdress});

    //             //finaladdress.* = finaladdress.* + delta.*;
    //         }
    //     }

    //     base_ptr += base.*.SizeOfBlock;
    //     const final = @as(*win.IMAGE_BASE_RELOCATION, @ptrFromInt(base_ptr));
    //     base = final;
    // }
    while (true) {}
}

test "simple test" {}
