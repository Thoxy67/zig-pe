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

    const dosheader: *win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_array_ptr));
    //std.debug.print("{any} \n", .{dosheader});

    const lp_nt_header = pe.get_nt_header64(addr_array_ptr, dosheader);
    //std.debug.print("{any} \n", .{lp_nt_header});

    pe.write_sections(addr_array_ptr, file_content, dosheader, lp_nt_header);

    pe.write_import_table(addr_array_ptr, lp_nt_header);

    // fix_base_relocations(baseptr, nt_header);

    // execute_image(addr_array_ptr, lp_nt_header);

}

// TODO : fn fix_base_relocations(baseptr, nt_header)

test "simple test" {}
