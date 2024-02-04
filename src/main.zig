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

    write_import_table(addr_array_ptr, lp_nt_header);
}

// TODO : Need to fix
fn write_import_table(baseptr: ?*anyopaque, nt_header: *win.IMAGE_NT_HEADERS) void {
    std.log.debug("\x1b[0;1m[-] === Get Write Import Table ===\x1b[0m", .{});
    const import_dir = nt_header.*.OptionalHeader.DataDirectory[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size == 0) {
        return;
    }
    var importDescriptorPtr: *win.IMAGE_IMPORT_DESCRIPTOR =
        @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(import_dir.VirtualAddress)) - 40);

    while (importDescriptorPtr.Name != 0 and importDescriptorPtr.FirstThunk != 0) {
        const dllNamePtr: [*]u8 =
            @ptrFromInt(@intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.Name)) - 40);

        const dllName = read_string_from_memory(dllNamePtr);

        std.log.debug("DLL : \x1b[34m{s}\x1b[0m\tFirstThunk : \x1b[31m0x{x}\x1b[0m\tName offset: \x1b[32m0x{x}\x1b[0m", .{
            dllName,
            importDescriptorPtr.FirstThunk,
            importDescriptorPtr.Name - 40,
        });

        const dll_handle = win.LoadLibraryA(dllName[0..99]);

        var thunkptr: usize = @intFromPtr(baseptr) + @as(usize, @intCast(importDescriptorPtr.unnamed_0.Characteristics)) - 40;

        while (true) {
            const thunk: [*]u8 = @ptrFromInt(thunkptr);
            const offset: usize = std.mem.readVarInt(usize, thunk[0..@sizeOf(usize)], std.builtin.Endian.little);

            if (offset == 0) {
                break;
            }

            const funcname = read_string_from_memory(@ptrFromInt(@intFromPtr(baseptr) - 40 + offset + 2));
            std.log.debug("{s}", .{funcname[0..99]});

            const funcaddress = win.GetProcAddress(dll_handle, funcname[0..99]);
            std.log.debug("{any}\n", .{funcaddress});

            thunkptr += @sizeOf(usize);
        }

        // Move to the next import descriptor
        importDescriptorPtr = @ptrFromInt(@intFromPtr(importDescriptorPtr) + @sizeOf(win.IMAGE_IMPORT_DESCRIPTOR));
    }
}

fn read_string_from_memory(baseptr: [*]u8) [*:0]const u8 {
    var temp: [100]u8 = undefined;
    for (0..100) |i| {
        temp[i] = baseptr[i];
        if (temp[i] == 0) {
            break;
        }
    }
    return temp[0..temp.len :0];
}

test "simple test" {}
