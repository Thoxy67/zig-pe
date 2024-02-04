const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    // const file_content = @embedFile("bin\\putty.exe");

    const file_name = "bin/putty.exe";
    const file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize));

    const header_size = pe.get_headers_size(file_content) catch |e| {
        std.log.err("cannot get header size : {}\n", .{e});
        return e;
    };
    const header = file_content[0..header_size];

    const image_size = pe.get_image_size(file_content) catch |e| {
        std.log.err("cannot get image size : {}\n", .{e});
        return e;
    };

    const addr_alloc: win.LPVOID = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT, std.os.windows.PAGE_READWRITE) catch |e| {
        std.log.err("cannot alloc virtual memory {}\n", .{e});
        return e;
    };

    const addr_array_ptr: [*]u8 = @ptrFromInt(@intFromPtr(addr_alloc));

    @memcpy(addr_array_ptr, header);

    const dosheader: *const win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_alloc));
    //std.debug.print("{any} \n", .{dosheader});

    const lp_nt_header: *const win.IMAGE_NT_HEADERS = pe.get_nt_header64(addr_alloc, dosheader);
    //std.debug.print("{any} \n", .{lp_nt_header});

    pe.write_sections(addr_alloc, file_content, dosheader, lp_nt_header);

    pe.write_import_table(addr_alloc, lp_nt_header);

    // fix_base_relocations(baseptr, nt_header);

    fix_base_relocations(addr_alloc, lp_nt_header);

    //pe.execute_image(addr_array_ptr, lp_nt_header);
}

// FIXME
fn fix_base_relocations(baseptr: ?*const anyopaque, nt_header: *const win.IMAGE_NT_HEADERS) void {
    _ = baseptr; // autofix
    const basereloc = nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (basereloc.Size == 0) {
        return;
    }

    //std.debug.print("{}, {}\n", .{ nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress });

    // //std.debug.print("{}\n", .{nt_header.OptionalHeader.ImageBase});

    // const diffaddress = @intFromPtr(baseptr) - nt_header.OptionalHeader.ImageBase;
    // _ = diffaddress; // autofix
    // //std.debug.print("{}\n", .{diffaddress});
    // const relocptr: *win.IMAGE_BASE_RELOCATION = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, nt_header.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
    // _ = relocptr; // autofix

    //std.debug.print("{any}\n", .{relocptr});

    // const entries: u32 = (relocptr.*.SizeOfBlock - @as(u32, @sizeOf(win.IMAGE_BASE_RELOCATION))) / 2;
    // std.debug.print("{}\n", .{entries});

    //while (@as(u32, relocptr.SizeOfBlock) != 0) {}

    //std.debug.print("{x}, {x}\n", .{ relocptr.*.SizeOfBlock, relocptr.*.VirtualAddress });
}

test "simple test" {}
