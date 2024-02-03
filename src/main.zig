const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const file_name = "bin/putty.exe";
    const file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize));

    const header_size = pe.get_headers_size(file_content) catch {
        std.debug.print("cannot get header size\n", .{});
        return;
    };
    const header = file_content[0..header_size];

    const image_size = pe.get_image_size(file_content) catch {
        std.debug.print("cannot get image size\n", .{});
        return;
    };

    const addr: win.LPVOID = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT, std.os.windows.PAGE_READWRITE) catch {
        std.debug.print("cannot alloc virtual memory\n", .{});
        return;
    };
    const addr_array_ptr: [*]u8 = @ptrFromInt(@intFromPtr(addr));

    @memcpy(addr_array_ptr, header);

    const dosheader: *win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr));
    //std.debug.print("{any} \n", .{dosheader});

    const lp_nt_header = pe.get_nt_header64(addr, dosheader);
    //std.debug.print("{any} \n", .{lp_nt_header});

    pe.write_sections(addr, file_content, dosheader, lp_nt_header);
}

test "simple test" {}
