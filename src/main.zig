const std = @import("std");
const win = @cImport(@cInclude("windows.h"));
const pe = @import("pe.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    // const file_content = @embedFile("bin\\putty.exe");

    const file_name = "bin/putty.exe";
    const file_content = try std.fs.cwd().readFileAlloc(gpa.allocator(), file_name, std.math.maxInt(usize));

    const header_size = pe.get_headers_size(file_content) catch |e| {
        std.debug.print("cannot get header size : {}\n", .{e});
        return;
    };
    const header = file_content[0..header_size];

    const image_size = pe.get_image_size(file_content) catch |e| {
        std.debug.print("cannot get image size : {}\n", .{e});
        return;
    };

    const addr_alloc: win.LPVOID = std.os.windows.VirtualAlloc(null, image_size, std.os.windows.MEM_COMMIT, std.os.windows.PAGE_READWRITE) catch |e| {
        std.debug.print("cannot alloc virtual memory {}\n", .{e});
        return;
    };

    const addr_array_ptr: [*]u8 = @ptrFromInt(@intFromPtr(addr_alloc));

    @memcpy(addr_array_ptr, header);

    const dosheader: *win.IMAGE_DOS_HEADER = @ptrCast(@alignCast(addr_array_ptr));
    //std.debug.print("{any} \n", .{dosheader});

    const lp_nt_header = pe.get_nt_header64(addr_array_ptr, dosheader);
    //std.debug.print("{any} \n", .{lp_nt_header});

    pe.write_sections(addr_array_ptr, file_content, dosheader, lp_nt_header);

    write_import_table(addr_array_ptr, lp_nt_header);
}

// TODO : Need to fix
fn write_import_table(baseptr: ?*anyopaque, nt_header: *win.IMAGE_NT_HEADERS) void {
    const import_dir = nt_header.*.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) {
        return;
    }

    std.debug.print("{any}\n", .{
        import_dir,
    });

    var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR =
        @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)));

    std.debug.print("{any}\n", .{
        importDescriptorPtr,
    });

    while (importDescriptorPtr.Name != 0) {
        const dllNamePtr: [*]u8 =
            @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.Name)));

        const dllName = read_string_from_memory(dllNamePtr);

        std.debug.print("{s} {x} {x}\n", .{
            dllName,
            importDescriptorPtr.FirstThunk,
            importDescriptorPtr.Name,
        });

        // Move to the next import descriptor
        importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR));
    }
}

fn read_string_from_memory(baseptr: [*]u8) []u8 {
    var temp: [100]u8 = undefined;
    for (0..100) |i| {
        temp[i] = baseptr[i];
        if (temp[i] == 0) {
            break;
        }
    }
    return temp[0..temp.len];
}

test "simple test" {}
