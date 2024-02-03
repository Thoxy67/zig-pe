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
    write_import_table(addr, lp_nt_header);
}

// TODO : Need to fix
fn write_import_table(baseptr: ?*anyopaque, nt_header: *win.IMAGE_NT_HEADERS) void {
    const import_dir = nt_header.OptionalHeader.DataDirectory[@as(usize, win.IMAGE_DIRECTORY_ENTRY_IMPORT)];
    if (import_dir.Size == 0) {
        return;
    }

    std.debug.print("\n{any}\n", .{import_dir.VirtualAddress});

    const ogfirstthunkptr: *win.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)));
    while (ogfirstthunkptr.Name != 0 and ogfirstthunkptr.FirstThunk != 0) {
        const ptr: usize = @intFromPtr(baseptr) + (ogfirstthunkptr.Name) - 40;

        std.debug.print("{}\n", .{ogfirstthunkptr.Name});

        const dllname = read_string_from_memory(@ptrCast(@as([*]u8, @ptrFromInt(ptr))));
        std.debug.print("{s} \n", .{dllname});
        break;
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
    return &temp;
}

test "simple test" {}
